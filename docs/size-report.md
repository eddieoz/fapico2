**Date:** 2026-10-03 (**the `uv: false` MakeCredential gate fix on
`fix/passkey-discovery`** — the PIN-set UV gate lifted itself for an explicit
`uv: false`, so such a request skipped `CTAP2_ERR_PUAT_REQUIRED`, fell through
to the presence gate and armed a touch with no PIN verified; wire-proven on
serial 94746395 (`uv` absent → `0x36`, `uv: true` → `0x36`, `uv: false` →
touch window closed with `0x2D`), fixed in both twins, regression-pinned in
`apps/fido/tests/uv_false_gate.rs`. See `.superpowers/sdd/report-uv-false-gate.md`.)
**Measured: `text` 818,424 → 818,436 B (**+12 B**); `.rodata` 18,716 B
(**0**); Berkeley `.bss` 421,768 B (**0**); RAM statics 421,964 B (**0**); main
stack zone 110,512 B (**0**). UF2 **3072 → 3072 blocks** (1 absolute preamble
+ 3071 ARM_S payload), **1,572,864 bytes, unchanged**. Shipping sha256
`da884eb0398c…` → **`6590ef49748ff6c173c38eebbf60a5d5cf3cccf2d5dde92a7f9a451256792725`.**
Command, verbatim: `./build.sh`, then `check_size_report.py`'s own
`measure_elf()` / `uf2_facts()`. `build.sh`'s own line for this build, unedited:

```
firmware/fapico2.uf2: 3072 blocks (1 absolute preamble + 3071 ARM_S payload), 1572864 bytes
6590ef49748ff6c173c38eebbf60a5d5cf3cccf2d5dde92a7f9a451256792725  firmware/fapico2.uf2
```

**The +12 B is layout, not a new feature, and it did not move the block
count.** The device-image edit removes a condition — the
`(!req.options_present || req.uv != Some(false))` term in
`device_core.rs::make_credential_inner` — so the honest expectation was ≤ 0 B;
at this size, LTO and branch-layout shifts dominate, and +12 B is the same
alignment-noise scale as the +24 B entry below. The 12 B landed inside the
last block's slack: the image stays 3,072 blocks / 1,572,864 B against the
**1536** KiB `FIRMWARE_FLASH_BUDGET_KIB`, so the ratchet passes with the same
**zero blocks** of headroom it had — the number the next change has to beat.
The `apps/fido/src/app.rs` half of the fix is the host twin, `#[cfg(feature =
"host")]`, **0 B** in this image; the 8 tests in
`apps/fido/tests/uv_false_gate.rs` are an integration-test binary, **0 B**.

---

**Date:** 2026-10-03 (**the `authenticatorSelection` presence gate on
`fix/passkey-discovery`** — CTAP2 `0x0B` answered `CTAP2_OK` in ~14 ms without
ever asking anybody, which claims "a user selected me" with no user involved;
CTAP2.1 §6.9 requires the authenticator to ask for user presence and answer
`CTAP2_OK` *only* if it is received. The arm is gated on `user_present()` now,
on both twins, and `0x0B` joined `presence_windowed` in
`firmware/src/hid_serve.rs` so the `UpRequired` can actually open a window
rather than leaving as a bare error frame.)
**Measured: `text` 818,400 → 818,424 B (**+24 B**); `.rodata` 18,716 B
(**0**); Berkeley `.bss` 421,768 B (**0**); RAM statics 421,964 B (**0**); main
stack zone 110,512 B (**0**); task-arena demand 21,944 B (**0** — no task
future grew; the stamp moved `2ebb12bd8466…` → `1e0e4aef25e4…` because the
fingerprint covers `firmware/src`, and it was re-measured with
`measure_task_arena.py`, the authority). UF2 **3072 → 3072 blocks** (1 absolute
preamble + 3071 ARM_S payload), **1,572,864 bytes, unchanged**. Shipping
sha256 `a822ff6b44b1…` → **`da884eb0398c1b2b4a6cd2ef1c71f9011fc5d8ea85247dfb42eff174babdbf11`.**
Command, verbatim: `./build.sh`, then `check_size_report.py`'s own
`measure_elf()` / `uf2_facts()`. `build.sh`'s own line for this build, unedited:

```
firmware/fapico2.uf2: 3072 blocks (1 absolute preamble + 3071 ARM_S payload), 1572864 bytes
da884eb0398c1b2b4a6cd2ef1c71f9011fc5d8ea85247dfb42eff174babdbf11  firmware/fapico2.uf2
```

**The +24 B is all `.text`, and the block count did not move.** It is the gate
itself: one `user_present(presence_tag_from_channel(current_channel))` call and
one `0x0B` comparison in the `presence_windowed` predicate. There is no new
function and no new table — the last UF2 block had slack, so 24 B landed inside
it. That is luck, not headroom: the image is 3072 of 3072 blocks and the next
block trips `FIRMWARE_FLASH_BUDGET_KIB`, so the 25 B version of this change
would not have built.

**This entry does not raise `FIRMWARE_FLASH_BUDGET_KIB`.** It stays **1536**,
the image stays on 3072 of 3072 blocks, and the slack stays zero — the number
the next change has to beat.

---

**Date:** 2026-10-03 (**the CTAPHID conformance fix on `fix/passkey-discovery`** —
`tests/pico-fido/test_055_hid.py`, seven failures, bisected to `686c36b`. Three
firmware corrections, all on the shipping CTAP-HID path: a `CTAPHID_INIT`
handshake may now preempt an in-flight transaction instead of being answered
`CHANNEL_BUSY` (which had no resynchronisation path out and wedged the channel
for every later command), a zero-length CTAPHID CBOR message is answered with a
CTAPHID ERROR frame carrying `INVALID_LEN` instead of a *successful* CBOR frame
carrying `INVALID_COMMAND`, and the emulator finally models a touch landing
inside the consent window. See `.superpowers/sdd/report-ctaphid-regression.md`.)
**Measured: `text` 818,376 → 818,400 B (**+24 B**); `.rodata` 18,716 B
(**0**); Berkeley `.bss` 421,768 B (**0**); RAM statics 421,964 B (**0**); main
stack zone 110,512 B (**0**); worst call chain 91,988 B (**0**, 6,316 B of
margin against the 98,304 B ceiling); task-arena demand 21,944 B (**0** — no
task future grew; the stamp moved `59c34a8dd4f7…` → `2ebb12bd8466…` because the
fingerprint covers `firmware/src`, and it was re-measured with
`measure_task_arena.py`, the authority). UF2 **3072 → 3072 blocks** (1 absolute
preamble + 3071 ARM_S payload), **1,572,864 bytes, unchanged**. Shipping
sha256 `306f5568f450…` → **`a822ff6b44b1077205587797b72d98723ff3716243c4b847787bd032c0c94d68`.**
Command, verbatim: `./build.sh`, then `check_size_report.py`'s own
`measure_elf()` / `uf2_facts()`. `build.sh`'s own line for this build, unedited:

```
firmware/fapico2.uf2: 3072 blocks (1 absolute preamble + 3071 ARM_S payload), 1572864 bytes
a822ff6b44b1077205587797b72d98723ff3716243c4b847787bd032c0c94d68  firmware/fapico2.uf2
```

**The +24 B is all `.text`, and the block count did not move.** Two of the three
corrections are near-free by construction — an extra `cmd != CTAP_HID_INIT`
comparison in the assembler, and one more constant on an existing reply — so
the 24 B is alignment and register pressure, not a new function. The third
correction is where the honesty is worth stating plainly: the natural place to
fix the missing CTAPHID keepalive was the **device's** dispatch, which is what
the C reference does (`pico-keys-sdk/src/usb/hid/hid.c:585-587` emits a
`0x01 PROCESSING` for every accepted CTAP2 command). That was built and
measured: **+164 B**, which is 1,572,864 → 1,573,376 B, i.e. **3,072 → 3,073
blocks — the one thing the ratchet exists to refuse.** So the touch is modelled
in the *emulator* instead (`firmware/src/emul_main.rs::emul_touch_lands_in_window`,
with the gate it needs added to the host twin `apps/fido/src/app.rs`, which is
`#[cfg(feature = "host")]` and contributes **0 B** to this image). The
observable consequence is the same or better: the emulator's makeCredential now
opens a **real** consent window and emits the board's own opening `0x01
PROCESSING` frame, which is what `test_055_hid.py::test_keep_alive` asserts —
whereas the device-side version would have satisfied the same assertion with a
frame no board ever sends.

**This entry does not raise `FIRMWARE_FLASH_BUDGET_KIB`.** It stays **1536**,
the image stays on 3072 of 3072 blocks, and the slack stays zero — which is
the number the next change has to beat, and is the reason a 164 B fix had to
be routed through the test double rather than the firmware.

---

**Date:** 2026-10-02 (**the boot-phase LED diagnosability ladder** — commits
`5b15f48`, `63c9009`, `d0a94ca`, `f96f3d7`. A post-mortem read channel for a
board that flashes cleanly and then never re-enumerates: nine rungs driven on
GPIO25, one short pulse per boundary crossed, released to the runtime before the
executor is entered. This is a **re-stamp only** for the image, and it is the
entry where the flash ratchet's last block of slack is spent — see "the slack is
now zero" below before reading anything else in it.)
**Measured: `text` 818,148 → 818,376 B (**+228 B**); `.rodata` 18,716 B
(**0**); Berkeley `.bss` 421,768 B (**0**); RAM statics 421,964 B (**0**); main
stack zone 110,512 B (**0**); worst call chain 91,988 B (**0**, 6,316 B of
margin against the 98,304 B ceiling); task-arena demand 21,944 B (**0** — no
task future grew; the stamp moved `014837326a49…` → `59c34a8dd4f7…` because the
fingerprint covers `firmware/src`, and it was re-measured with
`measure_task_arena.py`, the authority). UF2 **3071 → 3072 blocks** (1 absolute
preamble + 3071 ARM_S payload), 1,572,352 → **1,572,864 bytes**. Shipping
sha256 `3f46f624cc14…` → **`306f5568f4501f2039351c0f742ebe7dd67f2cfa87d4fc31ce6d35389be95448`.**
Command, verbatim: `./build.sh`, then `check_size_report.py`'s own
`measure_elf()` / `uf2_facts()`. `build.sh`'s own line for this build, unedited:

```
firmware/fapico2.uf2: 3072 blocks (1 absolute preamble + 3071 ARM_S payload), 1572864 bytes
306f5568f4501f2039351c0f742ebe7dd67f2cfa87d4fc31ce6d35389be95448  firmware/fapico2.uf2
```

**The +228 B is all `.text`, and it is one of three commits.** `5b15f48` is the
pure half — `fapico2_firmware::bootphase`, the encoding, the rung table, the
ordering contract and the release rule, in the *lib* rather than the bin so
`cargo test --lib` reaches it. Most of that is `#[cfg(test)]` and tables that
fold at compile time, so what it contributes to the shipping image is the
encoding arithmetic and the rung lookup. `63c9009` is ~40 lines turning a
`bootphase::Mark` into GPIO25 writes plus a local `busy_wait_us` (a copy, not a
call into `dbg` — the `dbg` module is feature-gated out of the default build, so
sharing it would un-gate the 12 KiB ring with it). `d0a94ca` is the nine
`mark!` call sites and `release()`. `f96f3d7` is `docs/bootsel.md` prose:
**0 B.**

**`.bss` did not move, and that is the useful fact here.** The ladder is nine
GPIO writes and a delay loop; it allocates nothing. A diagnosability feature
that had cost RAM would have been bought out of the main stack zone, which on
this build has 4 B of alignment slack and no unallocated SRAM at all — the same
`ALIGN(4)` arithmetic the 2026-09-30 entry describes. Nothing was bought from
anywhere, because nothing was needed.

**The block count moved this time: 3,071 before, 3,072 after.** The prior
re-stamp (US-1529, +164 B) did not cross a block boundary and the one before it
did not either; this one does, because 3072 × 512 = **1,572,864 B**, and that is
the first whole block above the old image. So unlike the last two entries the
size itself changed, and the sha256 changed with it for the ordinary reason.

**THE SLACK IS NOW ZERO. The last block of headroom was spent by the
boot-phase LED.** `FIRMWARE_FLASH_BUDGET_KIB` is **1536**, i.e.
`BUDGET_BYTES` = 1,572,864 B, and the shipping image is **1,572,864 B**. The
gate compares `SHIPPING -gt BUDGET_BYTES`, so 1,572,864 is not greater than
1,572,864 and **the ratchet passes — with nothing left over**. Write the
arithmetic down rather than rounding it: 1536 KiB = 3072 blocks, the image is
3072 blocks, the headroom is **0 blocks / 0 B**, and the very next block
(3,073 blocks, 1,573,376 B) trips it.

This matters more than the arithmetic suggests. The ratchet is a *regression*
detector, and it now fires for a reason unrelated to whatever change caused the
red. A maintainer who adds a string constant somewhere, or lets LTO land
differently on a different toolchain, gets a CI failure that names the flash
budget and offers exactly two readings — shrink it, or raise the number — when
the honest third reading is "this was already at the wall". The US-1519 raise
(1532 → 1536 KiB) bought one block and the epic said explicitly that one block
was the most informative number the ratchet could carry; that block is now
gone, spent on a diagnostic that a later author may not even know exists.

**The ratchet is NOT raised by this entry, and per US-1519's own acceptance
criterion it must not be unless the reason is written here.** The epic says:
*"if the ratchet bites, shrink the implementation rather than raise the
number — and if it must be raised, the reason is written in this document."*
It has not bitten. The image is at the ceiling, not over it. Raising 1536 →
1537 now would be spending a KiB of permanent, invisible budget to avoid a
sentence in a file that already contains the sentence.

**What the next growth costs, concretely.** The next 512 B of flash anywhere in
the firmware — one string table, one new applet stub, one monomorph that LTO
stops folding — makes the ratchet red. The response per US-1519 is to shrink,
and the honest list of what can be shrunk is short: this file has already
established that `emul_hid` is gated out (0 B to recover), that the `dbg` ring
is feature-gated (0 B to recover), and that the two SHA-512 call sites cannot
evict the stock `sha2` backend because `trussed`'s `hmac-sha512` mechanism still
reaches it (8.9× of latent win that is not collectable without dropping a PIV
algorithm attribute). There is one lever specific to this entry, and it is
already measured: **`FAPICO2_BOOT_LED=0` produces text 818,148 B** — byte-for-byte
the pre-LED baseline, which is the point, since the kill switch exists so a
build that cannot afford the ladder can drop it without editing code. It is
recorded here as a fact, not as a plan: setting it to make a gate green would
ship a board whose dark-boot failure mode is undiagnosable again, which is the
entire reason these +228 B were spent. `check_size_report.py` and the CI
flash-budget job will not notice the difference; a person debugging at 2am
will.

**The one claim in the entries below that this entry supersedes.** US-1519's
headroom paragraph and US-1529's restatement of it both say the headroom is one
512-byte block. As of this build that is **zero blocks**, and both have been
annotated in place below rather than silently rewritten — see the dated
correction notes there.

Prior header:

**Date:** 2026-10-02 (**US-1529 — `makeCredUvNotRqd` was a hard-coded lie;
derive it from PIN state.** The option was seeded `true` in
`Ctap2Info::default`, so a PIN-set device advertised support for a
non-discoverable-credential `makeCredential` with no UV — which the MC 8.1 gate
refuses with `0x36`. It is now computed from the same two facts that gate
reads. This is a **re-stamp only**: the ratchet is not touched, because the
shipping UF2 did not grow.)
**Measured: `text` 817,984 → 818,148 B (**+164 B**); `.rodata` 18,716 B
(**0**); Berkeley `.bss` 421,768 B (**0**); RAM statics 421,964 B (**0**); main
stack zone 110,512 B (**0**); task-arena demand 21,944 B (**0**, stamp
`014837326a490937…` still verifies against the current sources, so nothing was
re-measured); UF2 **3071 blocks** (**unchanged**, 1 absolute preamble + 3070
ARM_S payload), 1,572,352 bytes (**unchanged**). Shipping sha256
`4349e0ad29c6…` → **`3f46f624cc14…`.**
Command, verbatim: `./build.sh`, then `check_size_report.py`'s own
`measure_elf()` / `uf2_facts()`. `build.sh`'s own line for this build, unedited:

```
firmware/fapico2.uf2: 3071 blocks (1 absolute preamble + 3070 ARM_S payload), 1572352 bytes
3f46f624cc1431222cdfb22afc95f80562cb9ca70b465d3cca46c30d9c026fde  firmware/fapico2.uf2
```

**The +164 B is all `.text`, and it is all in one place.** `.rodata` did not
move, which is the useful fact: `"makeCredUvNotRqd"` was already a string
literal in `Ctap2Info::default` and only its *value* changed (`true` → `false`),
so no new key is emitted and the option map's footprint is unchanged. The
whole delta is therefore the one device-image call site —
`device_core.rs::handle_get_info` now does

```rust
info.set_option(
    "makeCredUvNotRqd",
    crate::ctap2::make_cred_uv_not_rqd(
        self.keystore.pin_state.pin_hash.is_some(),
        self.keystore.pin_state.always_uv,
    ),
);
```

`make_cred_uv_not_rqd(pin_set, always_uv) = !pin_set && !always_uv` has **no
standalone symbol in the release ELF** — `arm-none-eabi-nm … | grep
make_cred_uv_not_rqd` returns nothing — so it inlines at its call sites rather
than adding a called function and a prologue/epilogue pair. What costs 164 B is
the inlined body (two flag loads off `pin_state`, a second load to keep them
live across the CBOR insert, the `!a && !b` reduction, and `Ctap2Info::set_option`
— a 106 B out-of-line symbol — called one more time). That is the honest
shape of it: **164 B to stop the wire claiming a capability the device refuses**,
and to make the two twins unable to drift by construction.

**164 B, and the UF2 block count did not move: 3,071 before, 3,071 after.**
The UF2 grows in whole 512 B blocks, so a sub-block change cannot move the
block count; this one landed inside the last already-allocated block and the
image is byte-identical in length. The **sha256 did change**
(`4349e0ad29c6…` → `3f46f624cc14…`) because the payload bytes changed even
though the length did not — which is why this doc records the hash and not
just the size. A reader diffing only the block count would wrongly conclude
nothing was flashed.

**The ratchet is untouched, and so is its slack.**
`FIRMWARE_FLASH_BUDGET_KIB` stays at **1536**; this story does not raise it and
does not need to. Against the budget the slack is unchanged at **512 B** — the
same single 512-byte block of headroom US-1519's entry describes, since
1,572,352 B measured against 1,572,864 B is exactly one block.
> **Corrected 2026-10-02 by the boot-phase LED entry above.** The first two
> sentences of this paragraph are about US-1529 and are still true *of US-1529*;
> the 512 B figure is not true of the tree any more. The boot-phase LED spent
> the last block: the image is 3072 blocks / 1,572,864 B against a 1,572,864 B
> budget, so the slack is **0 B, zero blocks**, and the next block trips the
> ratchet. The 512 B above is left as written because it is what the gate
> compared against on that commit.

**Which edits in this story cost 0 B, named so this re-stamp is not read as
covering them.**

* **`apps/fido/src/app.rs`** — the host twin's identical copy of the fix — is
  `#[cfg(feature = "host")]`. Cost in the shipping image: **0 B.** Only
  `device_core.rs` is compiled for the device.
* The 8 tests in `apps/fido/tests/make_cred_uv_not_rqd.rs` are an integration
  test binary; **0 B.**
* The `docs/webauthn-discovery-ab.md` / `-baseline.md` updates are prose;
  **0 B.**
* **This document's re-stamp is 0 B**, including the ELF section table and the
  ELF summary above: both are regenerated from the ELF by
  `check_size_report.py`, so re-recording them is not an edit to the image.
* The comment blocks added next to the unchanged 8.1 gate in
  `device_core.rs` and `app.rs` cost **0 B**; the gate itself is byte-for-byte
  the same branch, which is the point — the advertisement was fixed to match
  the gate, not the reverse.

**The US-1519 headroom paragraph is still accurate, and was checked rather than
assumed.** It reads: *"The headroom is one 512-byte block, not zero… one more
block lands the image on exactly 1,572,864 — which is not greater than the
1,572,864 B ceiling, so it passes. Two blocks (1,573,376 B) is the first size
that trips it."* Re-derived against this build: 3071 × 512 = 1,572,352 B
measured; 1536 KiB = 1,572,864 B; the ratchet fires on `SHIPPING -gt
BUDGET_BYTES` (`ci.yml`), so 1,572,864 B is **not** greater than 1,572,864 B and
passes, while 1,573,376 B is. Every term in that paragraph is unchanged by
US-1529, because US-1529 did not move the block count. The earlier,
overstated phrasing ("the next ordinary growth is a red again, immediately")
remains corrected in place and is **not** restored by this entry.
> **Superseded 2026-10-02 by the boot-phase LED entry above.** The paragraph
> quoted here is accurate *as of US-1529* and is left as written for that
> reason, but it no longer describes the tree: the boot-phase LED took the
> image from 3071 to 3072 blocks, so "one more block lands the image on exactly
> 1,572,864" has already happened. The headroom is now **zero blocks**, and
> 1,573,376 B is not a hypothetical size any more — it is the size of the next
> 512 B of flash anyone adds.

Prior header:

**Date:** 2026-10-02 (**US-1519 — the passkey-discovery epic, merged.** The
image grew, the ratchet bit, and the EPIC's acceptance criterion is "shrink the
implementation rather than raise the number". Shrinking was attempted first and
did not pay; the ratchet is raised 1532 → **1536 KiB** and the reason is below,
feature by feature, with the zero-byte edits named so a later reader does not
misattribute them to this raise.)
**Measured: `text` 815,576 → 817,984 B (**+2,408 B**); Berkeley `.bss` 420,704 →
421,768 B (**+1,064 B**); task-arena demand 21,976 → **21,944 B** (**−32 B**,
re-measured, stamp re-stamped `897931090a328186…`); UF2 **3061 → 3071 blocks**
(1 absolute preamble + 3070 ARM_S payload), 1,567,232 → **1,572,352 bytes**.
Shipping sha256 `0f4e6189e4ea…` → **`4349e0ad29c6…`**.**
Command, verbatim: `./build.sh`, then `check_size_report.py`'s own
`measure_elf()`. `build.sh`'s own line for this build, unedited:

```
firmware/fapico2.uf2: 3071 blocks (1 absolute preamble + 3070 ARM_S payload), 1572352 bytes
4349e0ad29c68d703e36beb32d2e698107aa999ef102f092d107b494f1f1a6b4  firmware/fapico2.uf2
```

**The baseline was rebuilt, not assumed.** The epic base `517529f` was checked
out into a scratch worktree and built from scratch with this toolchain: it
produces **1,567,232 B / 3061 blocks / sha256 `0f4e6189e4ea…`**, which is the
2026-10-01 entry below, exactly. So the +2,408 B of `text` and the +10 blocks
below are this epic's, not accumulated drift. The same worktree build is where
the per-symbol attribution comes from (`arm-none-eabi-nm -S`, symbol-size delta
base → head).

**What the +2,408 B of `text` is, symbol by symbol.** Only the entries large
enough to matter are listed; the remainder is `OUTLINED_FUNCTION_*` churn and
`num-bigint-dig` monomorph renumbering that nets out under 100 B.

| symbol | base | head | delta |
|---|---:|---:|---:|
| `tasks::__hid_task_task0::poll` (the monomorphised serve loop) | 4,888 | 6,548 | **+1,660** |
| `fido::device_app::FidoApp::process_u2f_with_store` | 1,432 | 0 | **−1,432** |
| `tasks::DeviceFido<hid_serve::FidoDispatch>::process_u2f` | 0 | 1,412 | **+1,412** |
| `hid_serve::reply::<tasks::DeviceHid>` | 0 | 672 | +672 |
| `tasks::reply_hid` | 498 | 0 | **−498** |
| `fido::device_app::FidoApp::process_ctap2_with_store` | 25,696 | 25,868 | +172 |
| `hid_serve::close_window` | 0 | 144 | +144 |
| `tasks::HidInWriter<hid_reply>::sent_or_failed` | 0 | 76 | +76 |
| `tasks::DeviceHid<hid_serve::HidIo>::read_report` | 0 | 80 | +80 |
| `tasks::persist_hid` | 72 | 0 | **−72** |
| `heapless::Vec<u8, 7609>::extend_from_slice` | 36 | 0 | **−36** |

**The two ±1,4xx rows are a move, not a cost, and they are the single largest
thing in this entry.** US-1524 put the emulator on the shipped serve loop, which
meant the U2F dispatch had to stop being a method on `FidoApp` (reachable only
from a `&mut FidoApp` the serve loop does not own) and become a method on the
new `hid_serve::FidoDispatch` trait, implemented over `&mut FidoApp`. The work
moved 1,432 B out of `process_u2f_with_store` and 1,412 B into the trait impl —
**net −20 B** — and the same holds for the reply path: 672 B into
`hid_serve::reply::<DeviceHid>` against 498 B out of `tasks::reply_hid`,
**net +174 B** for the one that also grew a `HidNote::ReplyDropped` arm and a
bounded write. Reading "+1,660 on the poll body" without the two removals beside
it is how a move gets mistaken for a 2.4 KB feature.

**What the remaining +1,660 B of `hid_task::poll` actually is.** `HidIo` and
`FidoDispatch` are monomorphised exactly once for the device (`DeviceHid`,
`DeviceFido`), so this is not duplicated monomorphisation — it is the serve loop
itself, now carrying: the `redrive_window` pass (US-1509's non-blocking consent
window), the CTAP2 **and** U2F park arms, `close_window`'s
`end_window`/`touch_prompt`/release pairing, the keepalive rate limiter
(US-1506), the `CTAPHID_CANCEL` arm (US-1505), the same-channel contention
refusal (US-921), and the two deadline-bounded USB transfers (US-1504, whose
`embassy_time::with_timeout` pulls its machinery into this path for the first
time). None of it is on a path that existed before the epic.

**What the +1,064 B of `.bss` is, exactly and only.** `boot::PENDING_UP`, and
nothing else:

```
200004d0 00000428 b ...fapico2_firmware4boot10PENDING_UP...            # 1,064
```

1,064 = the pinned **1,024 B** `PENDING_UP_PAYLOAD_MAX` payload buffer + 40 B
of slot state (`occupied`, the `WindowTicket`, `payload_len`, the two-byte
refusal + its length, `last_keepalive_ms`, `keepalive_sent`, with the struct's
alignment). `arm-none-eabi-nm -S` shows **exactly** 1,064 B of new `.bss` and
the gate's `RAM statics` figure moved 420,904 → 421,968 B, also exactly +1,064:
the entire RAM delta of this epic is that one static. The 1,024 B bound is
pinned by `pending_up::tests::the_payload_bound_is_1024_and_is_never_parked_over`
and is the mechanism that stops a hostile oversize request converting into a
30 s wait (US-1510) — shrinking it would be removing a reviewed fix, so it was
left alone. `hid_task`'s arena pool, `HID_RESP`, the app statics and the store
buffers are all byte-identical to the base build.

**RAM, which is the tighter constraint, absorbed the whole thing.** The **main
stack zone fell 111,576 → 110,512 B** to make room; `bss + stack zone + .data
= 532,476 B` against 532,480 B of SRAM either way. There is still **no
unallocated SRAM**, so the 1,064 B was not free — it was bought out of the
stack zone. The **worst call chain is 91,988 B against the 98,304 B ceiling
(6,316 B of margin)**, which the `redrive_window` re-assert pass did not eat;
it was 91,972 B at the base. `check_boot_chain.py` PASSes.

**The task arena went *down*, by 32 B, and its stamp was re-measured.**
`measure_task_arena.py` re-run under nightly over the merged tree:

```
measured 6 task pools, 21,944 B total, stamp 897931090a328186…
  button_poll_task: 56      ccid_task: 8,600    embassy_main: 168
  hid_task: 12,328           led_heartbeat_task: 56    usb_task: 736
```

21,944 B in a **32,772 B** arena = **1.49×** (floor 1.25×), against 21,976 B /
1.50× at the base: `hid_task`'s future is **32 B smaller** even though its
compiled poll body is 1,660 B larger. That is not a contradiction — the consent
`loop` the epic removed was an `async` state machine whose frame was charged to
the future, and the replacement parks its state in `boot::PENDING_UP` instead.
**The growth was paid in `.bss` and traded back out of the arena.** The stamp
is byte-exact over source text, so the 26 commits in the epic invalidated it
regardless of whether any future grew; `check_boot_chain.py` failed closed on it
until `measure_task_arena.py` was re-run, which is the guard working.

**Shrinking was tried, and here is what it measured.** Three levers, in order
of how promising they looked:

1. **`emul_hid.rs` in the device image** — the obvious suspect, a 1,035-line
   new module that exists for the emulator. **It was already gated out.**
   `lib.rs:132` carries `#[cfg(feature = "emulation")]`, and
   `arm-none-eabi-nm … | grep -c emul_hid` on the release ELF returns **0**.
   Cost in the shipping image: **0 B.** Nothing to recover.
2. **`#[cfg(test)]` instrumentation** — `HidServe::reads` and
   `HidServe::blocked_live_passes` (US-1509's blackout detector) are both
   `#[cfg(test)]` fields. Cost in the release image: **0 B.**
3. **Outlining the loop's two big async helpers** — `#[inline(never)]` on
   `hid_serve::redrive_window` and `hid_serve::dispatch`, on the theory that an
   `async fn` inlined across many `.await`s duplicates its state machine at
   `opt-level = "z"`. **Measured: 817,984 → 818,412 B, +428 B.** Worse, not
   better, because both are reached from exactly one call site apiece and there
   is no duplication to remove — only a prologue and an epilogue. Reverted;
   the committed figure is the 817,984 B above.

There is no fourth lever that is not "remove a reviewed fix". The capFlags
change, the bounded HID reads and writes, Phase C's non-blocking consent
window, `CTAPHID_CANCEL`, the keepalive protocol, the emulator parity
migration and the error-table alignment were each reviewed and are each the
subject of a US-number; **the only way to reach 1532 KiB from here is to undo
one of them**, so the number is raised deliberately instead, which is what the
EPIC asks for in that case.

**Which edits in this epic cost 0 B, named so this raise is not read as
covering them.**

* The **emulator parity migration** (US-1524) — `emul_main.rs` dropping its
  own assembler, reply framer, dispatcher and consent `loop` for
  `hid_serve`'s — costs **0 B on the device image**. It removes code from a
  binary that is not flashed.
* `HidServe::reads` / `blocked_live_pass` / `blocked_live_passes` — the US-1509
  blackout instrument — are `#[cfg(test)]` and cost **0 B**.
* The task-arena **re-stamp** and this document re-stamp cost **0 B** of
  `text`; the stamp is a byte-exact hash, not code.
* `FidoApp::process_u2f_with_store` → `FidoDispatch::process_u2f` is **net
  −20 B**, i.e. the largest single item in the epic is a move that came out
  slightly ahead.

**The raise, and what it buys.** `FIRMWARE_FLASH_BUDGET_KIB` **1532 → 1536**.
1536 KiB = 1,572,864 B against a measured 1,572,352 B, so the slack this leaves
is **512 B**. That is tighter than the ~1.5 KiB the previous two raises left,
and deliberately so: 1536 is the smallest whole-KiB value the shipping image
fits under, which is the most informative number this ratchet can carry.
> **Spent 2026-10-02.** That 512 B was consumed in full by the boot-phase LED
> entry at the top of this document. The ratchet was **not** raised to replace
> it.

**The headroom is one 512-byte block, not zero.** The ratchet fires on
`SHIPPING -gt BUDGET_BYTES` (`ci.yml`), and one more block lands the image on
exactly 1,572,864 — which is **not** greater than the 1,572,864 B ceiling, so
it passes. Two blocks (1,573,376 B) is the first size that trips it. An
earlier draft of this paragraph said the next ordinary growth is "a red again,
immediately"; that is one block optimistic, and the block is the smallest unit
the UF2 format can grow in, so it is the difference between "the next change
trips this" and "the change after next does".
> **Superseded 2026-10-02.** Written when the measured image was 3,071 blocks,
> this said the headroom was one block and the block after that would be the
> first to trip the ratchet. The **boot-phase LED entry** at the top of this
> document is the "one more block": the image is now 3,072 blocks /
> 1,572,864 B, exactly on the ceiling, so the headroom is **zero blocks** and
> 1,573,376 B is the first size that trips it — which is what this paragraph
> already predicted, one commit earlier than it expected it. The two earlier
> corrections in this paragraph are a history of the same ratchet losing room;
> this is the third and the last block.

Prior header:

**Date:** 2026-10-01 (**Re-measurement after the revert of the `cargo-deps` group
PR #2.** No feature changed; the *resolved dependency closure* did, so every
number below is re-taken rather than carried.)

**Measured: `text` 813,568 → 815,576 B (**+2,008 B**); Berkeley `.bss` 420,692 →
420,704 B (**+12 B**); task-arena demand 17,760 → **21,840 B** (re-measured, not
carried — see below); UF2 **3061 blocks** (1 absolute preamble + 3060 ARM_S
payload), 1,567,232 bytes. Shipping sha256 **`0f4e6189e4ea…`.**
Command, verbatim: `./build.sh`, then `check_size_report.py`'s own
`measure_elf()`. `build.sh`'s own line for this build, unedited:

```
firmware/fapico2.uf2: 3061 blocks (1 absolute preamble + 3060 ARM_S payload), 1567232 bytes
```

**Why every figure moved when no code did.** The `cargo-deps` group PR
(`3f020ecc6e`, merged then reverted as `904b646`) had rewritten `Cargo.lock`
across three major-version generations — `rand_core` 0.6 → 0.10 and RustCrypto
0.10/0.12/0.8/0.1 → 0.11/0.13/0.9/0.2. Those were unbuildable against
`trussed` 0.2 / `trussed-core` 0.2, which pin `rand_core = "0.6"` and the
`digest` 0.10 line, so the revert put the whole lockfile back. The restored
closure compiles to a different image than either the pre-PR or post-PR tree
did: +2,008 B of `text` and +12 B of `.bss`. Neither delta is a feature and
neither is a regression to chase — they are what this dependency set weighs.

**The task arena was re-measured, not assumed.** `check_boot_chain.py` failed
closed on the arena stamp: `TASK_ARENA_DEMAND_B_STAMP` is byte-exact over
`firmware/src` plus the resolved version of every package in the firmware's
closure, and the lockfile move invalidated it. The stamp is the guard, not the
measurement — `measure_task_arena.py` under nightly is the authority — so it was
re-run and the demand re-stamped at `d4a732983b0db5eb…`. The new figure,
**21,840 B against a 32,772 B arena (1.50×, floor 1.25×)**, is the measured
one; the previous 17,760 B was stale and its larger apparent headroom was not
real. Both the arena and the worst call chain (91,972 B against the 98,304 B
ceiling) pass.

**The only source change in this commit is clippy, and it is byte-neutral in
intent**: `CmDialect`'s hand-written `Default` impl became `#[derive(Default)]`
with `#[default]` on `Ctap2` in **both** the host twin (`app.rs`) and the device
twin (`device_core.rs`), and the host twin's write-only `sub_params_cbor` field
was dropped. That field was parsed and stored but never read — the host twin
deliberately rebuilds the signed params from typed fields while the device twin
signs the raw bytes, a split pinned by
`device_full_set.rs::device_twin_credmgmt_mac_scope_differs_from_host_for_0x01_and_0x02`,
which still passes.

---

**Date:** 2026-09-30 (**US-OTP-HID: the Yubico OTP HID transport** — a second
HID interface, the YK4 feature-report state machine, and the composite
`HidInterfacesHandler` that routes both — plus the `encCredStoreState` and
P-521 key-generation fixes below). The image grew, so the measurement is
re-taken rather than carried; the direction is the useful part, so it is stated
first.
**Measured: `text` 811,648 → 813,512 B (**+1,864 B**); Berkeley `.bss` 420,476 →
420,692 B (**+216 B**); task-arena demand 17,760 B (**unchanged** — the OTP-HID
handlers are synchronous, strictly inside the USB control transfer, and spawn
no task); UF2 **3,053 blocks** (1 absolute preamble + 3,052 ARM_S
payload), 1,563,136 bytes. Shipping sha256
**`293d8e3f821a…`**.**
Command, verbatim: `./build.sh` (which runs `cargo build --release` and stages
the UF2), then `check_size_report.py`'s own `measure_elf()`. `build.sh`'s own
line for this build, unedited:

```
firmware/fapico2.uf2: 3053 blocks (1 absolute preamble + 3052 ARM_S payload), 1563136 bytes
```

**The growth is the feature, and it is bought twice over.** The +1,860 B of
`text` is the second HID interface's descriptors, the composite handler's two
extra routing arms, and the `otp_hid` frame state machine (`FRAME_RX`,
`FRAME_TX`, sequence counters, CRC-16). The +216 B of `.bss` is that state
machine's buffers. None of it is on a path that existed before.

**Three smaller edits in the same change cost zero bytes**, and are worth
recording because "it grew" would otherwise absorb them silently:

- `HidControlHandler` — 48 lines (struct + `Handler` impl) — was **dead**. The
  composite `HidInterfacesHandler` replaced it and routes strictly more (CTAP
  and OTP control requests), so the old type had zero code references and the
  linker had already dropped it. Deleting unreachable code cannot move the
  image, and did not.
- `bytes.len() <= MAX_IDENTITY_STRING - 1` → `bytes.len() < MAX_IDENTITY_STRING`
  in `StoredName::new` — clippy's `int_plus_one`; identical semantics, identical
  codegen.
- the unused `Persist` import in `firmware/src/otp_hid.rs` — `persist_one` is a
  free function, not a trait method, so no code was behind it.

**RAM, which is the tighter constraint, absorbed the `.bss` growth.** `.bss`
grew 216 B and the **main stack zone shrank to match**, 111,804 → 111,588 B;
`bss + stack + .data` is 532,476 B against 532,480 B of SRAM either way. That
4 B is not a margin — it is `ALIGN(4)` slack in `cortex-m-rt`'s `link.x`, where
`_stack_start` is pinned to the top of RAM and `_stack_end` is *derived* from
the statics. **The stack zone is elastic: statics grow into it.** What fails a
regression is the linker refusing to place `.bss`, and behind that the
`check_boot_chain.py` call-chain ceiling (`CHAIN_CEILING` = 98,304 B), which
turns a link error into a dark board. Both still pass, and the gate below
enforces them.

**The −168 B is dead code leaving the image, not a behaviour change**, and the
four security fixes that shipped alongside it cost less than the code they
replaced. Nothing on a request-serving path grew, so `.bss`, the boot chain and
the async frame are all byte-identical:

- `apps/fido/src/extensions.rs` deleted outright — a 79-line `pub mod` of
  CTAP2 extension data types (`CredProtect`, `LargeBlobSupport`, `AuthConfig`,
  `ExtensionResults`, …) with **zero** references anywhere in the tree, not even
  from the host tests that could have used them. They were a stub, not an
  unfinished feature: nothing constructed or consumed them.
- `cfb256_decrypt` (`platform/src/ckey.rs`) — the AES-256-CFB unwrap for the
  legacy OpenPGP DEK form, never called. Removing it also drops the `cfb-mode`
  dependency, which nothing else pulled in.
- `pin_hash_dec` / `pin_encrypt_legacy` / `pin_decrypt_legacy`
  (`apps/fido/src/crypto.rs`) — the `IV=0` v1-PIN-protocol trio, unreferenced;
  the live v2 path uses `pin_hash_enc` and the `pin` module, both kept.
- `BOARD_PINS`, `internal_select`, `is_hid_connected` — three unreferenced
  `pub` items the `dead_code` lint cannot see, because `pub` in a library crate
  is never reported.
- `apps/piv/Cargo.toml` lost `p256`, `p384`, `ecdsa`, `elliptic-curve` and
  `rand_core` — declared for the ADR-0001 ECC work that `apps/piv/src/crypto.rs`
  has not implemented (PIV currently serves key *import* only, over
  AES/3DES/HKDF).

**The security fixes, and why they are not free-but-small.** Two are net
negative or neutral on size; the framing one is positive by design.

- **Factory reset no longer discards its delete results** (`firmware/src/boot.rs`).
  The four secure-store deletes that remove the FIDO keys, the FIDO hkey, the
  OpenPGP DO records and the wrapped DEK were `let _ =`; only the trussed
  internal-FS format was checked. A device that had never been provisioned
  takes `NotFound` on those four, so propagating every error would have made
  the common case fail — `ignore_absent` maps `NotFound` to success (nothing
  to wipe) and fails `0x6F00` on anything else, and `RESET_GENERATION` is now
  bumped only after the deletes land. Without that ordering a task could
  re-persist, and re-seal, the keys the reset was meant to destroy.
- **The store image nonce is now injective** (`platform/src/store_v3.rs`).
  `entries_digest` hashes `index ‖ key_len ‖ key ‖ val_len ‖ val` instead of a
  bare `key ‖ val`, so `("ab","c")` and `("a","bc")` no longer collide — under
  the old encoding both derived the byte-identical nonce
  `fe ee b6 63 f8 7e d2 9d fe cb c5 ad`, which is the AES-GCM nonce-reuse
  condition the module's own doc claims cannot arise. The heap `seal_image`
  path and the device's windowed emission now call one shared function so the
  framing cannot drift between them. `platform/tests/store_v3.rs` pins it.
  The two paths can only be compared byte-for-byte on a single entry — the
  device store serializes in slot order, the host store holds a `BTreeMap`
  (key order), so multi-entry images legitimately differ — which is exactly
  what `device_and_heap_sealing_agree_byte_for_byte` asserts.
- **Zeroize gaps closed**: `derive_kbase` now clears its salt the way
  `derive_drbg_seed` already did (`platform/src/ckey.rs`), and the CTAP2
  `reset` path in `apps/fido/src/device_core.rs` clears `pin_token` before
  dropping it, matching the invariant `device_app::clear_session_state`
  already stated in code.
- **No `.expect()` on a remount** (`platform/src/trusted_backend/device.rs`).
  `panic = "abort"` means a panic there bricks the token with no unwinding and
  no USB enumeration, and the function already returns `bool` for exactly this
  case two lines above.

**Date:** 2026-09-29 (**the boot-entropy bound, and US-919 becoming a build
parameter**). The image moved, so the measurement is re-taken rather than
carried; the direction is the useful part, so it is stated first.
**Measured: `text` 811,972 → 811,816 B (**−156 B**); Berkeley `.bss` 420,476 B
(**unchanged**); boot chain 91,964 B (**unchanged**); async frame 15,744 B
(unchanged); task-arena demand 17,768 → 17,760 B (**−8 B** — `embassy_main`
176 → 168 B; re-measured with `measure_task_arena.py`, which is the
authority, and re-stamped `f2ce91cca9f09b75…`).** Shipping sha256
**`68d884035771…`**, UF2 **3,046 blocks** (1 absolute preamble + 3,045 ARM_S
payload), 1,559,552 bytes.
Command, verbatim: `cargo build --release --target thumbv8m.main-none-eabi`
then `arm-none-eabi-size target/thumbv8m.main-none-eabi/release/fapico2-firmware`
— i.e. `check_size_report.py`'s own `measure_elf()`, so these are the two
numbers the gate reads.

**The −156 B is a measurement of something removed, not of something added,
and it was checked in both directions before this line was written.**
`ensure_boot_entropy` was the last site drawing entropy through `&mut impl
Trng` — that is, through `embassy-rp`'s `Rp2350Trng`, whose driver is the
unbounded `while !success` retry at `trng.rs:220-243`. Routing it through the
bounded `Rp2350Probe` left that driver with no caller at all, and LTO dropped
the function whole:

```
$ arm-none-eabi-nm target/…/release/fapico2-firmware | grep -c blocking_wait_for_successful_generation
1        # at the pre-fix tip
$ arm-none-eabi-nm target/…/release/fapico2-firmware | grep -c blocking_wait_for_successful_generation
0        # after
```

A symbol that is present in one build and absent in the next says more about
what the shipping image contained than any figure in this document does, and
it is the difference between "the fix cost 156 bytes" and "the fix removed a
function that could not return". The size falling is the correct reading.

**Date:** 2026-09-29 (**US-1005, the migration-nonce bound — D-10 closed**). The
device image moves, so the measurement is re-taken rather than carried; the
direction is the useful part, so it is stated first.
**Measured: `text` 811,724 → 811,976 B (**+252 B**); Berkeley `.bss` 420,484 →
420,476 B (**−8 B**); boot chain 92,712 B (**unchanged, byte-identical**); async
frame 15,744 B (unchanged); task-arena demand 17,768 B (unchanged, stamp
re-stamped).**
Command, verbatim: `cargo build --release --target thumbv8m.main-none-eabi`
then `arm-none-eabi-size target/thumbv8m.main-none-eabi/release/fapico2-firmware`
— i.e. `check_size_report.py`'s own `measure_elf()`, so these are the two
numbers the gate reads.

**RAM statics 420,672 B** = `.data` + `.bss` + `.uninit`; main stack zone
111,804 B — the two plus `.data` account for 532,476 of the board's 532,480 B
of SRAM, so there is **no unallocated RAM**. (The `text` / `.bss` / UF2 figures
for this entry are its own header above and the evidence block below; restating
them here is what made an old measurement shadow the current one in
`check_size_report.py`, which reads the first match in the document.)

**Two ceilings, both enforced by `check_size_report.py`.** `text` ≤
**3,670,016 B** (flash, long-standing). `bss` ≤ **434,176 B** (RAM, added by
US-1010) = 532,480 B of SRAM in the generated `memory.x` − the 98,304 B
main-stack ceiling `check_boot_chain.py` enforces, imported rather than
restated. The second is the one that decides whether the board boots: a static
past it does not fail the link, it shrinks the main stack region until the
boot path overflows it — DARK-BOOT-1, where the 32-entry secure store's
+36,288 B of bss did exactly that. Headroom today: **13,700 B of bss**, and
the chain's own margin is **6,340 B** (98,304 − 91,964), not the 19,840 B the
zone arithmetic suggests, because the gate binds on `min(ceiling, zone)`.

```
firmware/fapico2.uf2: 3046 blocks (1 absolute preamble + 3045 ARM_S payload), 1559552 bytes
edfa46e13636959533bbbd4e17e0483f9e1d6c1661fe9c06feec1fe0dd964388  firmware/fapico2.uf2
```

**Why the image grew, and why nothing else did.** The +252 B is the migration
nonce's new draw path: `platform::trng::try_migration_nonce` (the bounded
`probe_bytes` plus the all-zero refusal), the second `Rp2350Probe::new` and
its `require_advancing` on the boot path, and the two refusal arms in
`DeviceMigrationHandler` that turn a refusal into a card error (with a
three-way log line naming which of the bounded wait's refusals fired — the
`ClockStalled` case is a fact about the instrument, not the peripheral, and
D-12 exists because collapsing it into the others is what made the 2026-09-29
dark boot unreadable). It replaces an
`embassy-rp` `blocking_fill_bytes` call that was *already* in the image, so
this is not new entropy machinery — it is the cost of a bounded wait in a place
that had an unbounded one, which is the trade D-10 asked for.

The −8 B of `.bss` is `MIG_TRNG` (`Rp2350Trng`, an `embassy-rp` driver handle)
replaced by `MIG_PROBE` (`Rp2350Probe`: a ZST peripheral token, a ZST timer and
two configuration bytes). The −8 is the driver's own state, not a moved static;
no secret store, keystore or migration buffer moved.

**The boot chain is byte-identical at 92,712 B**, which is the number that
mattered for the stack budget. The new draw is reached from
`DeviceMigrationHandler::complete`, which is on the request-serving chain — and
it did not lengthen it: `draw_blocks` is the *same* function the DRBG seed path
already ran, so the chain it adds is a call the worst-case chain already
contained, while what it removes is the call to `blocking_fill_bytes`'s
unbounded loop, which was already there too. The arena stamp moved
(`e9d36927…` → `22128565…`) because `platform/src/trng.rs` is in the firmware's
dependency closure, not because a future grew — re-measured with
`python3 tests/scripts/measure_task_arena.py`, every per-task size unchanged
(ccid 8,600 / hid 8,144 / usb 736 / embassy_main 176 / button 56 / led 56).

The regenerated artefact is committed so `firmware/fapico2.uf2` keeps matching
a fresh build, which is the drift `check_size_report.py` exists to catch.

**Prior headers:**

**Date:** 2026-09-29 (**I-1 / I-4 / US-1008 / US-1083 — the final whole-branch
review fix pass**). Four stories touched the device path and the measurement is
re-taken here rather than carried.
**Measured: `text` 811,768 → 811,776 B (+8 B); Berkeley `.bss` 420,476 →
420,484 B (+8 B); boot chain 92,712 B (unchanged); async frame 15,744 B
(unchanged); task-arena demand 17,768 B (unchanged, re-measured and
re-stamped `e9d369275e9fbb5c…`).**
Command, verbatim: `cargo build --release --target thumbv8m.main-none-eabi`
then `arm-none-eabi-size target/thumbv8m.main-none-eabi/release/fapico2-firmware`
— i.e. `check_size_report.py`'s own `measure_elf()`, so these are the two
numbers the gate reads.

**Where the +8 B / +8 B come from, stated rather than asserted.** Four changes
and only two can move a section, so it is worth being precise about which:

* **US-1083** adds `Otp::lock_state`, `LockWord`, `LockField` and
  `Provisioner::check_lock_state` to `platform/src/boot_key.rs`. That module
  has no caller in this tree — it is a library with no reachable trigger — so
  a linker that drops unreferenced code contributes **0 B** here. The B is in
  the *type metadata* and monomorphised trait glue the section accounting
  attributes to `platform`, not to reachable instructions.
* **US-1008** changes one call site from `fatal_boot` to `defmt::warn!` plus a
  `match`, and adds a large doc comment. `defmt::warn!` is shorter than
  `fatal_boot`'s `defmt::error!` + `loop {}`, so this is the most likely
  source of the `.text` delta.
* **I-4** changes two `device_keystore.rs` call sites to a fallible form and
  adds a `SecureStoreError::Entropy` variant with a `Display` arm. `boot.rs`
  maps the new variant, so the format string is reachable.
* **I-1** adds two register writes inside a `#[cfg(target_arch = "arm")]`
  module. `rnd_src_sel` is 2 bits, so the instruction delta is single-digit
  bytes — consistent with +8, but **not attributed**, because attributing 8
  bytes across four changes needs per-change measurement this report does not
  have. The honest statement is: the total is +8 B, it is 0.001 % of the
  ceiling, and no claim is made about which of the four produced it.

**The `.text` / `.rodata` split above is carried, not re-derived.** The gate
reads Berkeley `text` and does not break it down, and the method this document
used for the split is not reproduced in the gate; re-deriving it from a
different `objdump` invocation would produce numbers that do not sum to the
Berkeley figure they are supposed to decompose, which is worse than carrying
the previous split and saying so. Berkeley `text` and Berkeley `.bss` — the
two figures `check_size_report.py` actually compares — are re-measured.

**Prior headers:**

**Date:** 2026-09-29 (**US-1080, board definition files** —
`firmware/boards/<board>.toml` + `firmware/build.rs` generating `memory.x`).
A re-measurement for a story whose whole claim is that it changes *no* size:
the board file moved the pins, the USB identity and the flash partition out of
`.rs` literals, and the device image had to come out the same size.
**Measured: `text` 811,768 B (unchanged); `.text` 759,984 B (unchanged);
`.rodata` 18,524 (unchanged); `.data` 196 (unchanged); Berkeley `.bss` 420,476
(unchanged); boot chain 92,712 B (unchanged); async frame 15,744 B (unchanged);
task-arena demand 17,768 B (unchanged, re-measured and re-stamped).**
UF2 **3,038 → 3,046 blocks**, shipping sha256 `a5a7459757d7…` →
**`a7ac74126703…`**. The build-script line, verbatim:

```
firmware/fapico2.uf2: 3046 blocks (1 absolute preamble + 3045 ARM_S payload), 1559552 bytes
a7ac7412670372e6a1e4aa2d7e19b7fae561b9fe338e0de6b19078bc7825e4ab  firmware/fapico2.uf2
```

**Read that UF2 line carefully: US-1080 contributed 0 of those 8 blocks.** The
image grew before this story and the committed artefact was never regenerated
to match. Measured on this tree with the change stashed: the *baseline* release
build also produces 3,046 blocks / 1,559,552 B, against a committed artefact of
3,038 blocks / 1,555,456 B. Three bytes of the shipping image differ between
the baseline ELF and the US-1080 ELF, in the code region, and none of it is
this story's — the whole `board` module is `const`, evaluated at compile time,
and contributes no instructions. The regenerated artefact is therefore
simultaneously (a) the one this story's build produces and (b) eight blocks
larger than what was checked in before it started. See "The stale shipping
artefact" below for why it was stale and what it means for the ratchet.

**Why the numbers did not move, which is the point of the story.** The
generated `memory.x` is partition-identical to the hand-written one it
replaced — `FLASH 0x10000000/4032K`, `SECURE 0x103f0000/64K` — and
`firmware/src/boot.rs`'s `SECURE_PRIMARY_OFFSET` and
`platform::trusted_backend::device::FLASH_SIZE` are now *derived* from the same
`flash_size_kb` that produced the linker script, so a board change moves all
three together or none. `platform/tests/board_def.rs` asserts the partition
identity directly, and
`pico2_partition_is_unchanged_from_the_hand_written_memory_x` exists because
getting it wrong would not be a link error: it would move a provisioned unit's
two secure image slots out of the region the linker reserved, and a `.uf2`
reflash does not clear NOR flash, so every such unit would boot to what looks
exactly like a factory-fresh device.

**The stale shipping artefact.** `firmware/fapico2.uf2` is a committed,
CI-gated binary, and CI compares it against a fresh build
(`cmp /tmp/fapico2-a.uf2 firmware/fapico2.uf2`). It had drifted: the previous
entry in this file records "UF2 3,038 blocks (unchanged — the shipping UF2 is a
checked-in release artifact, not rebuilt by this gate)", which is exactly the
gap — `check_size_report.py` reads the *committed file's* hash and block count,
so it stayed green while the artefact did not match the build, and the note in
the previous entry is the moment the drift became visible and was not acted on.
The 3 KiB by which the ratchet is now exceeded is therefore **inherited, not
incurred**; `FIRMWARE_FLASH_BUDGET_KIB` has been raised from 1520 to 1524 in
`.github/workflows/ci.yml` to discharge it, with US-1080's own contribution
being zero. The alternative — restoring the stale artefact and leaving CI red
on a build the story did not produce — would have hidden a pre-existing debt
behind a green checkmark.

**Date:** 2026-09-29 (**US-1070, the rolled SHA-512 compression** —
`platform::sha512`, a `digest`-trait drop-in that replaces stock `sha2`'s
unrolled soft backend at the two SHA-512 call sites the EPIC names
(`apps/fido/src/stateless.rs` HKDF-SHA-512, `apps/oath/src/oath_core.rs`
HMAC-SHA-512). A re-measurement because `check_size_report.py` went red on
it — and because the sign of the number is the interesting part).
**Measured: `text` 810,904 → 811,768 B (+864 B)**; `.text` 759,120 → 759,984
(+864); `.rodata` 18,524 (**unchanged**); `.data` 196 (unchanged); Berkeley
`.bss` 420,476 (**unchanged**); RAM statics 421,500 (unchanged); main stack
zone 111,804 B (unchanged); UF2 **3,038 blocks** (unchanged — the shipping
UF2 is a checked-in release artifact, not rebuilt by this gate), shipping
sha256 `a5a7459757d7…` (unchanged).

**The image grew, and that is the finding, not a surprise.** The EPIC's
expectation was that a rolled compression is *smaller* than the unrolled one,
and the compression itself is — but the image is the sum of everything in the
closure, and the unrolled one is still in it. Measured with
`arm-none-eabi-nm -S` on this build:

| symbol | bytes |
|---|---|
| `sha2::sha512::compress512` (stock, 80 rounds unrolled) | **10,544** |
| `fapico2_platform::sha512::compress` (rolled, 16-word circular schedule) | **1,188** |
| `Sha512Core::finalize_fixed_core` | 124 |
| `Sha512Core::update_blocks` | 64 |

So the port is **8.9× smaller than the code it replaces** — 1,376 B of new
`.text` against a 10,544 B function. It is also genuinely rolled, not merely
written in a loop: the disassembly is 420 lines with three conditional
branches and a back-edge, where the stock function's 10,544 B is what LLVM
produces when it unrolls.

**Why the net is +864 B anyway.** Two independent reasons, both worth writing
down rather than discovering later:

1. **Nothing was removed.** Stock `sha2`'s SHA-512 is still linked, because
   other users in the closure reach it — `trussed`'s `hmac-sha512` mechanism
   (`platform/Cargo.toml:29`, via `trussed_core::mechanisms::HmacSha512`,
   whose `sign`/`verify` are present in this image) and the OpenPGP stack
   behind it. Swapping two call sites adds a second implementation; it does
   not evict the first. Deleting the stock backend means dropping the
   `hmac-sha512` trussed feature and with it an OpenPGP PIV algorithm
   attribute — a functional change with its own compatibility surface, and
   emphatically not this story.
2. **The two call sites only ever inlined a slice of it.** Even a call site
   that used *nothing* else pays only for what it used; the 10,544 B is a
   single shared function, so the −512 B implied by (1,376 new − 864 net) is
   the stock glue that became unreachable, not the compression.

**The honest one-line summary: US-1070 is a latency change that costs
+864 B of flash, and the size win is latent until the stock backend leaves
the closure.** That is the right trade at 22.1 % of the ceiling, and it is
also the number a future story that *does* remove `sha2`'s SHA-512 will
collect.

**The stack did not move, and that is worth stating too.** The worst call
chain is **92,712 B, byte-identical**, with the per-root chain table
(92,712 / 91,964 / 91,952 / 81,136 / 18,468 / 18,468) unchanged and the
second root still the same **748 B** below the worst. `check_async_frame.py`
still passes at 15,744 B against the 24,576 B ceiling, and the task-arena
measurement stamp `a15b8b2859debb58…` verified current without a re-measure
(`python3 tests/scripts/measure_task_arena.py --check` → `ok`) — correctly,
because the swap adds no `unsafe`, no static and no `async` frame: `compress`
is a plain `#[inline(never)]` function over eight `u64`s and a 128-byte
stack array, reached from two call sites that were already on the request
path, not the boot path.

**Date:** 2026-09-29 (**US-1030, the OATH credential-key seal** —
`ckey::OathSeal` (the C `"OATH"`-magic AES-256-GCM record) plus the OATH
applet's boot re-seal, its per-key monotonic generation counter, and the
`HKDF` nonce derivation. A re-measurement because `check_size_report.py`
went red on it).
**Measured: `text` 809,608 → 810,904 B (+1,296 B)**; `.text` 757,928 →
759,120 (+1,192), `.rodata` 18,420 → 18,524 (+104); Berkeley `.bss` 420,380
→ **420,476 B (+96)**; RAM statics 420,576 → **421,500**; main stack zone
111,900 → **111,804 B (−96)**; UF2 **3,038 blocks** (unchanged — the shipping
UF2 is a checked-in release artifact, not rebuilt by this gate), shipping
sha256 `a5a7459757d7…` (unchanged).

**What the +1,296 B bought, and where it went.** The GCM seal/unseal pair
(`OathSeal::seal` / `OathSeal::open`), the two HKDF derivations in
`OathSeal::derive` and the nonce KDF in `OathSeal::nonce_for` are `.text`;
the `"OATH"` magic, the version byte, the `"OATH/SEAL-NONCE/v1"` label and
the `OathSeal` field names are `.rodata`. The **only** new RAM is **+96 B of
`.bss`** — the `OathSeal` (C GCM key ‖ nonce key ‖ AAD) that now lives in
the `OathApp` static slot — and the main stack zone gives exactly that back
(−96 B), which is the accounting you want to see: the seal context is one
struct in a `static mut`, not a per-boot allocation and not a task frame.
**The worst call chain did not move at all: 92,712 B, unchanged.** That is
the number that mattered most going in — `OathApp::boot_in_place` is
`#[inline(never)]` and sits on the boot path, and a per-key GCM in
`load_stream` could easily have added a kilobyte of AES key schedule to the
worst chain. It did not: the frame fits inside what the chain already had,
and the measurement is mechanical (`check_boot_chain.py`, US-957), not
estimated.

**The chunked-store cost, which is the one that is not free.** A sealed
credential key is `key_len + 33` bytes and carries a 10-byte generation
object, so a full 68-slot table is **+43 B per credential = +2,924 B** over
the pre-US-1030 encoding. `persist_state` then reports failure and keeps the
dirty flag (the pre-existing, documented behaviour — see `oath_core`'s module
docs). This is a real reduction in how many credentials a single unit can
hold and it is stated here rather than discovered in the field; the escape
hatch, if the ceiling ever bites, is shortening the generation object (e.g. a
32-bit counter with a wrap refusal), not removing the seal.

**Corrected by US-1010 (2026-09-29) — the "8,432 B logical cap" quoted here
was never reachable, and the real ceiling is smaller than the byte arithmetic
suggests.** A chunked rewrite writes the new generation into the buffer *not*
holding the current set and retires the old buffer's parts only afterwards, so
a full-width value transiently needs `2 × MAX_PARTS` physical entries. The
tree carried `MAX_PARTS = 17` against `DEV_MAX_ENTRIES = 24`: `2 × 17 = 34 > 24`,
so the first full-width rewrite returned `SecureStoreError::Full` and the
8,432 B figure was a documented capacity the device never served. `MAX_PARTS`
is now **12** — the largest value satisfying `2 × MAX_PARTS ≤ 24`, asserted at
compile time in `platform/src/secure_store.rs` — and the logical bound is
**5,952 B**. `DEV_MAX_ENTRIES` was **not** raised: that costs 568 B of sealed
partition image and ~580 B of bss *per entry* on a build with zero
unallocated RAM, the same MSPLIM constraint that hardware-rejected 32 entries.

The ceiling is set by the **rewrite peak**, not the byte count.
Measured on the real store (`apps/oath/tests/oath_capacity.rs`): a maximal
credential is 182 B of stream, 30 of them are 5,460 B = 12 parts, and the 31st
— 5,642 B — is *still 12 parts*, and still fits 5,952 B. It does not need a
13th part. What stops it is the peak of the double-buffered rewrite, which holds
the live generation and the one being written at once, plus the one entry this
app keeps outside the chunked table (the US-1030 seal high-water mark). The
30th is reachable because it is the first credential to reach 12 parts and
reaching them rewrites *from* 11: `11 + 12 + 1 = 24 ≤ 24`. The 31st is a
same-width `12 → 12` rewrite: `12 + 12 + 1 = 25 > 24`. **The OATH ceiling is 30
maximal credentials**, and a consequence worth stating rather than hiding: a PUT
that *replaces* a credential at 30 is a same-width rewrite, so it is accepted
(`0x9000`) and then not made durable. The `~42` implied by 8,432 B ÷ ~195 B was
wrong twice over: a byte bound the device could not meet, divided by a
per-credential cost that is 182 B, for a store whose real limit is set by parts.
`MAX_CREDS = 68` in `oath_core.rs` is a `heapless` table bound, never a
capacity claim.

**Cost of the US-1010 change: −20 B `text`, 0 B `bss`, −748 B boot-chain
stack.** `MAX_PARTS` is not a type parameter, so no allocation moved — `bss`
is byte-identical. The stack fell because `MAX_LOGICAL_LEN` appears in
on-stack decode buffers (`DeviceKeystore::load`, the OATH stream load);
shrinking the bound by 2,480 B shrank those frames, and the boot chain went
92,712 → 90,232 B. The worst chain is now the `App::process` vtable root at
91,964 B (a task-poll root at 90,232 B is second) against the 98,304 B
ceiling: **6,340 B of margin, up from 5,592 B**.

**Date:** 2026-09-29 (**US-1020, the presence handshake instrumentation** —
`firmware/src/presence.rs` now stamps one event per press / arm / discard /
window / grant on the runtime's monotonic clock and counts them; a
re-measurement because `check_size_report.py` went red: the counter block and
the event hook cost **+160 B `text` and +44 B `bss`**, and the `.bss` move is
the 40-byte counter block living in the presence runtime's static slot.
Beneath that: the 2026-09-29 dark-boot clock fix — the entropy
wait now checks that its own wall clock is counting before it spends the
budget** — a re-measurement because `check_size_report.py` went red: the
fix adds a runtime liveness check to the default `await_ready` body and a
clock-proof token to the device constructor). **Measured: `text` 809,288 →
809,448 B (+160 B), then → 809,608 B (+160 B)**; Berkeley `.bss`
**420,336 → 420,380 B (+44)**; UF2 **3,037 → 3,038 blocks**, shipping sha256
`eb48c0bbc7f7…` → `77edc4ea935a…` → **`a5a7459757d7…`**.

**What US-1020's +160 B bought, and what it did not change.** `.text`
757,768 → 757,928 (+160) and `.rodata` 18,420 (**unchanged**); `.data` (196 B)
unchanged; Berkeley `.bss` 420,336 → 420,380 (+44) and the RAM statics
420,532 → 420,576 — the presence runtime's `PresenceCounters` block (ten
`AtomicU32`), which is the **only** new RAM in the image. `__sheap`
`0x20066ab8` → `0x20066ae4` and the **main stack zone 111,944 B → 111,900 B**
(move down by the 44 B of statics; the zone is the leftover between `__sheap`
and `_stack_start`, so more statics is *less* stack). The **worst call chain
is unchanged at 92,712 B** — `PresenceRuntime::note` is `#[inline(always)]`
and holds its counters in the runtime's static slot, not in a task future, so
the request-serving path charged by `check_boot_chain.py` gained no frame; the
async-task frame is unchanged at 15,744 B and the task-arena demand is
unchanged at 17,768 B (the stamp was re-measured only because its
fingerprint covers the firmware sources). Nothing is a new allocation.

**What the clock fix's +160 B bought, and what it did not change.** `.text` 757,672 →
757,768 (+96) and `.rodata` 18,356 → 18,420 (+64); `.data` (196 B), Berkeley
`.bss`, the RAM statics, `__sheap` (`0x20066ab8`) and the **main stack zone
(111,944 B)** are all unchanged, and the **worst call chain is unchanged at
92,712 B** against the 98,304 B ceiling. The task-arena demand is unchanged
at 17,768 B; the stamp was re-measured because the fingerprint covers the
firmware sources, not because any spawned future grew. The addition is the
liveness branch in `TrngProbe::await_ready` and the `ClockReady` token path
in `Rp2350Timer` — the `.rodata` share is the `ClockStalled` format string.
None of it is a new allocation and none of it is a deeper frame, so the
stack warning this branch carries is untouched: the change is on the boot
path but adds no future to a boot root.

Prior header (the RS-KEY-ADOPT final-review fix batch, tip I-1 —
a re-measurement because `check_size_report.py` was red against this
document: routing the OATH boot RNG pool through the DRBG changes the device
ELF). **Measured: `text` 808,688 → 808,792 B, +104 B**; Berkeley `.bss`
**420,336 B (unchanged)**; UF2 **3,035 blocks** (+1), shipping sha256
`805e872d42ec…` → **`834bc4505f23…`**.
Prior header (US-1011 + US-1012, the FIDO counter batching — a correction
re-measured because the gate was red; those two stories *shrank* the image):
**Measured: `text` 808,732 → 808,688 B, −44 B**; Berkeley `.bss`
420,328 → 420,336 B, **+8 B**; UF2 **3,034 blocks** (unchanged), shipping
sha256 `e70dc34be002…` → **`805e872d42ec…`**.

**Why the gate was red, and why the image got *smaller*.** US-1011 removed a
whole-keystore rewrite from every `getAssertion` and US-1012 added a restore
path; the net effect on `text` is **−44 B**. The document still carried the
US-1010 figures, so `check_size_report.py` compared 808,732 against a
measured 808,692 and failed. Re-measured the same way `69cbb84` did —
`./build.sh` on the stable toolchain, then `arm-none-eabi-size` — and **no
figure below was hand-edited to match the gate**.

**What the +8 B of `.bss` is.** The `Decode` enum that replaced the
`slack == 0` proxy for "is this a restore" in the snapshot decoder: a
discriminant the compiler cannot fold, because `decode` is `#[inline(never)]`
and takes the mode by value. 8 B of `.bss` in exchange for making the
grant/spend pairing unrepresentable apart, which is the same trade this
codebase already makes at `to_cbor` and `load`.

**Command and toolchain.** `./build.sh` (which is
`cargo build --release --target thumbv8m.main-none-eabi` followed by
`python3 firmware/uf2gen.py`), then
`arm-none-eabi-size` / `arm-none-eabi-size -A` /
`arm-none-eabi-nm -S`. **Stable** toolchain — `rustc 1.98.1
(48a229cea 2026-09-01)`, the `stable` channel pinned by
`rust-toolchain.toml`. No nightly was used for any figure on this page; the
one figure in the tree that *needs* nightly is the task-arena demand, and it
is measured by `tests/scripts/measure_task_arena.py` under `cargo +nightly`
(see "Main-stack demand" below). The UF2 was regenerated into `/tmp` and
`cmp`'d against the committed artifact: **byte-identical**, so the sha256
below is reproducible, not a one-off.

**The RAM side moved too, and by less — but the stack headroom is the figure
to read.** `statics` grew 8 B, taking the **main stack zone from 111,952 B to
111,944 B**. The worst call chain is **92,712 B**, up 756 B from US-1010's
91,956 B: 748 B of that is US-1012's `load`, which became a tail call to
`decode` with the window folded in, and the remaining **8 B is this fix's**
bounded `probe_bytes` sanity draw. So `check_boot_chain.py` still PASSes but
its headroom fell from 6,348 B to **5,592 B**; `check_async_frame.py`
PASSes at 15,744 B against the 24,576 B absolute ceiling; and the task arena
is **17,768 B in a 32,772 B pool (1.84×, floor 1.25×)** — the *demand* is
unchanged, but the measurement **stamp** moved and
`measure_task_arena.py` was re-run to refresh it, because the fix does touch
the firmware closure `main.rs` sits in. That is the gate working: it refused
to publish a headroom figure from a stamp whose inputs had moved.

> **Read the chain's headroom, not the zone's margin.** 19,232 B of the
> 111,944 B zone remains (17.2 %), which reads comfortable. The binding
> number is 92,712 B against a 98,304 B ceiling — **5,592 B** — and the
> *second* root is **91,964 B, only 748 B below the worst**, so the two task
> chains move together and headroom on this path is thinner than the headline
> margin suggests. **This fix spent 8 B of that 748 B**, which is what the
> review's stack warning was about: routing a boot path through a bounded
> probe is not free, and on this branch it is measured rather than assumed.
> The next story that grows a future here must re-measure with
> `python3 tests/scripts/measure_task_arena.py` (needs nightly) and re-run the
> chain gate.

**Size gate: 811,776 B `text` against the 3,670,016 B ceiling — 2,858,240 B
free (77.9 %), 22.1 % of the ceiling used.** Nothing is near a ceiling, and
nothing was raised to make this fit. For the **RP2040 2 MB** sizing gate that
the parent workspace imposes, 811,768 B is **38.7 %** of 2,097,152 B, i.e.
1,285,384 B spare — the RP2040 is not the binding constraint for this
change. Prior headers:)
**Date:** 2026-09-28 (**US-1010, the RS-KEY-ADOPT HMAC-DRBG** — the first
measurement of the entropy work on the device path, and a re-baseline this
document was due because `check_size_report.py` had gone red on it).
**Measured: `text` 806,824 → 808,732 B, +1,908 B**; Berkeley `.bss`
418,980 → 420,328 B, **+1,348 B**; UF2 3,027 → **3,034 blocks**
(3034 blocks), shipping sha256 `071b245e46b9…` → **`e70dc34be002…`**.

**What the +1,908 B of `text` is.** The HMAC-DRBG core
(`platform/src/drbg.rs`), the fuse seed source with its per-instantiate and
per-reseed TRNG nonce draw (`platform/src/drbg_seed.rs`), and the
`RngCore` backend in front of the hardware TRNG
(`trusted_backend/device.rs`) — plus the SHA-256/HMAC they are built on,
which this image did not previously carry at that size. The **+1,348 B of
`.bss`** is the DRBG's own state: a reseed counter, a reseed-interval
constant's storage and the per-task scratch the seeded generator needs,
resident for the life of the process because a DRBG that re-derives its
state on every call is not a DRBG.

**The RAM side moved, and that is the figure to read.** `statics` grew
1,348 B, which pushed `__sheap` up and **shrank the main stack zone from
112,340 B to 111,952 B**. The worst call chain grew with it, 90,268 B →
**91,956 B**, so the remaining SRAM margin fell from **+22,008 B (19.6 %)
to +19,996 B (17.9 %)**. `check_boot_chain.py` still PASSes (98,304 B
ceiling, 6,348 B of chain headroom), `check_async_frame.py` still PASSes
(15,736 B frame against the 24,576 B absolute ceiling), and the task arena
re-measures at **17,768 B in a 32,772 B pool (1.84×, floor 1.25×)** with its
stamp re-verified against the post-DRBG sources. **The task-arena demand did
not grow at all** — the DRBG did not enlarge any spawned future, and only
the measurement *stamp* had gone stale; re-measuring with
`measure_task_arena.py` is what established that.
**Date:** 2026-09-28 (the **device identity block** — AAGUID, USB
manufacturer, USB product and VID:PID moved behind one build-time block, and
the default AAGUID moved from the borrowed RS-Key value to fapico2's own.
**Measured: `text` 804,880 → 806,824 B, +1,944 B**; `.bss` 418,916 → 418,980 B,
+64 B; UF2 3,019 → **3,027 blocks**, shipping sha256 `071b245e46b9…`.

**What the +1,944 B is.** The resolver itself is a few hundred bytes of const
evaluation that collapses at compile time; the rest is the AAGUID appearing in
two more places — the `identity` module *and* the `apps/fido` re-export of it,
which the existing `vendorff`/`vendor41` code reads through — plus the two
runtime name fields in the PHY record, which is CBOR-map storage and so costs
`code`, not RAM. The +64 B of `.bss` is the two `Option<IdentityName>`
placeholders: 31 bytes of buffer and a length each, rounded to the linker.

**The RAM figure did not move, and that is the point of the design.** The two
new fields are `Option`s that stay `None` until an operator writes a name, so
the statics cost is the placeholder, not a string. `.bss` at +64 B against a
+7,412 B merge is the difference between a feature that has somewhere to store
state and one that always does.

Stack and arena: worst call chain 90,204 → **90,268 B** against a 112,276 B
main stack zone, margin **+22,008 B (19.6 %)**; task arena re-measured at
17,768 B in a 32,772 B pool with its stamp re-verified. Prior headers:)
**Date:** 2026-09-28 (`feat/picompat` → `fix/openpgp` merge — the first
measurement of the two workstreams **in the same binary**, and the one the
PICOForge-COMPAT cross-epic gate G-1 exists to force. Neither branch could
account for the other's flash: the EPIC says so in as many words
("neither epic accounts for the other's headroom"), and this is the number
that follows from not doing that. **Measured: `text` 776,920 → 804,880 B,
+27,944 B**; `.bss` 411,504 → 418,980 B, **+7,412 B of new RAM statics**;
UF2 2,910 → **3,027 blocks** (3027 blocks), shipping sha256 `071b245e46b9…`.

**The RAM figure is the one to read, and it is a regression in headroom, not
a breach.** `statics` grew 7,412 B, which pushed `__sheap` up and *shrank the
main stack zone* from 119,752 B to 112,276 B. Against that, the worst call
chain also grew — 84,452 B → 90,268 B, the request-serving path through the
`App` vtable plus its task frame. The margin therefore fell from **+35,300 B
(29.5 %) to +22,136 B (19.7 %)**. `check_boot_chain.py` still PASSes (its
ceiling is 98,304 B), and the task arena re-measures at 17,768 B in a 32,772 B
pool, 1.84x against a 1.25x floor, with its stamp re-verified against the
post-merge sources.

That is the honest shape of the merge: the stack still fits with ~22 KB to
spare, and it fits with noticeably less room than either branch had on its
own. A follow-up that adds another appleted transport should re-run both
figures before assuming the ceiling is where it was. Prior headers:)
**Date:** 2026-09-27 (US-972 — the DO C5 fingerprint fix, and the first
change in a while that *adds* flash. `Persistent::set_key` cleared a key's
fingerprint on the removal path but wrote none on the set path, so after a
card-side `GENERATE` the public key changed while DO C5 stayed byte-identical
— a stale fingerprint a host believes, which is worse than none. The fix adds
a SHA-1 and a v4 public-key packet assembler to the vendored opcard
(`vendor/opcard/src/fingerprint.rs`). **Measured: `text` 775,388 → 776,920 B,
+1,532 B**; `.rodata` 17,576 → 17,632 B, +56 B; **no RAM figure moves at all**
— `.data` 196, `.bss` 411,504, `.uninit` 1,024, `_stack_end`, the 119,752 B
main stack zone, the 84,452 B worst call chain, its 35,300 B (29.5 %) margin
and the 17,744 B / 32,772 B task-arena demand are all bit-identical to the
US-966 tip, which is what a `no_std` constant-table change should look like.
UF2 2,904 → **2,910 blocks**, shipping sha256 `d33f8a92202c…`. The
fingerprint is computed when the creation date arrives (`PUT DATA
CE/CF/D0`), not at GENERATE — see "What US-972 changed" below for why the
brief's original placement is not merely inconvenient but impossible. Prior
headers:)
**Date:** 2026-09-27 (US-966 — Brainpool P-384r1 deferred to a follow-up
release, P-256r1 kept. **Measured: `text` 941,444 → 775,388 B, −166,056 B
(−17.6 %)**; `.rodata` −1,128 B; **no RAM figure moves at all** — `.data`,
`.bss`, `.uninit`, `_stack_end`, the 119,752 B main stack zone, the 84,452 B
worst call chain, its 35,300 B (29.5 %) margin and the 17,744 B / 32,772 B
task-arena demand are all bit-identical to the US-964 tip. UF2 3,553 → 2,904
blocks. The only non-flash edit is the arena *stamp* — the demand constant
itself did not move, its measurement inputs did (see "What US-966 changed"
below). Prior headers:)
**Date:** 2026-09-26 (US-964 — the guard that guards, the scrub residual, the
arena constant. I1 made `tests/scripts/check_advertise_serve_coupling.py`
actually reach the reduced build it measures, assert the
`default-features = false` edge on `fapico2-platform` that the reduced
configuration exists only because of, and read the serving-table row count
its old `REPORT` regex threw away;
`apps/openpgp/tests/advertise_serve.rs` now derives "served" from `BACKENDS`
in every configuration instead of hardcoding `false` behind
`#[cfg(not(...))]`, and the gate is a CI job rather than a script nothing ran.
I2 dropped the restored RSA scrub's `sign_count == 0` clause, which
`set_sign_alg`'s `delete_key(KeyType::Sign, …)` could leave true while the
card was already wedged. I3 replaced the hand-copied
`TASK_ARENA_DEMAND_B` with a stamped measurement that the boot-chain gate
refuses to believe once its sources move. Only I2 touches linked code, and it
is **−8 B of `text` and nothing else**: `.text` 889,488 → 889,480, every RAM
figure and both call-chain margins unchanged (statics 412,724 B, main stack
zone 119,752 B, worst chain 84,452 B, margin 35,300 B / 29.5 %), UF2 3,553
blocks — one comparison removed from a boot-path branch. The arena stamp is
`pub` in the firmware *lib* and no device code references it, so LTO drops it
and `.rodata` does not move. Prior
headers:)

# RP2350 Flash Size Report

**Date:** 2026-09-27 (re-baseline at the US-161/162/163 tip, `feat/picocompat`,
after the RS-Key **Rescue** applet (`apps/rescue`, AID `A0 58 3F C1 9B 7E 4F 21`,
CLA `0x80`) joined the CCID dispatcher — a **+1,768 B `text`**, **+72 B `bss`**
and **+7 UF2 blocks** step, and the device dispatcher growing `5 → 6`). The
prior re-baseline was the same day at `4181968` after the RS-Key vendor LED
applet (`apps/vendor_led`, AID `F0 00 00 00 01`) joined it, the one before that
at `e1c95be` after the OTP factory-wipe path gained its
`SecureStore::delete(STATE_SLOT_V1)`, the one before that at `35f39ab` after
Phases A–E, and the one before that 2026-09-26 (US-956). See
"Re-baseline 2026-09-27 (US-161/162/163 Rescue applet)" for the delta,
"Re-baseline 2026-09-27 (US-160 vendor LED applet)" for the one before it,
"Re-baseline 2026-09-27 (factory-wipe v1 record delete)" for the one before
that, "Re-baseline 2026-09-27" for the Phase D+E one, and "Phase D+E delta" for
what that code is.

**Prior baseline (2026-09-26):** US-956 — the device **could not boot** at the US-951 tip:
the statics claimed 527,420 B of the 532,480 B SRAM, leaving a 5,056 B stack
zone against a 117,828 B boot call chain. This story right-sized two statics
from measurement and moved the boot call chain off the stack: statics
527,420 → 412,732 B, stack zone 5,056 → 119,744 B, **boot** chain
117,828 → 67,288 B. **US-957 corrected the headline margin**: 67,288 B was the
*boot* chain only — the gate could not see the vtable hop onto the
request-serving path, where all of RSA, secp256k1 and Brainpool actually live.
The true worst-case chain is **88,348 B**, so the margin is **31,396 B
(26.2 %)**, not 52,456 B (43.8 %). Full derivation, including the re-verified
statics that were *not* cut and why: `docs/tasks/us956-ram-right-sizing.md`.)

**Board:** Raspberry Pi Pico 2 (RP2350, Cortex-M33) — the only supported target
**Binary:** `fapico2-firmware` release ELF (`thumbv8m.main-none-eabi`,
`--release`, `lto = "fat"`, `panic = "abort"`)
**Measurement:** `arm-none-eabi-size <ELF>` (Berkeley accounting — the same
number the CI gate uses) for the `text` gate, and `arm-none-eabi-size -A` for
the per-section figures. **`text` is what the gate constrains. `data` and `bss`
are BOTH RAM** — reporting Berkeley `bss` alone is the original sin this
document was corrected for in US-951 and that correction is preserved here.

## Current measurement (re-measured 2026-09-29 at the clock-fix tip)

**This is the authoritative current measurement.** Reproduce with
`./build.sh` on the **stable** toolchain (`rustc 1.98.1 (48a229cea
2026-09-01)`); see "Reproduction" at the end of this document for the
verbatim session. Every figure below came out of that build; none was
adjusted to match a gate.

Berkeley summary (`arm-none-eabi-size`, `target/thumbv8m.main-none-eabi/release/fapico2-firmware`):

```
   text	   data	    bss	    dec	    hex	filename
 809608	      0	 420380	1229988	  12c4a4	fapico2-firmware
```

Per-section (`arm-none-eabi-size -A`) — **`.data` and `.bss` listed
separately, because Berkeley folds the `.data` load image into `text`**:

<!-- BEGIN measured ELF sections (check_size_report.py) -->
| section | bytes | addr | in RAM? |
|---|---:|---:|:---:|
| `.secure_partition` | 32,768 | `0x103f0000` | **no** — NOLOAD flash address space |
| `.vector_table` | 276 | `0x10000000` | no (flash) |
| `.start_block` | 20 | `0x10000114` | no (flash) |
| `.text` | 766,460 | `0x10000200` | no (flash) |
| `.rodata` | 18,716 | `0x100bb400` | no (flash) |
| `.data` | 196 | `0x20000000` | **yes** — initialized, copied from flash by crt0 |
| `.gnu.sgstubs` | 0 | `0x100bfde0` | non-alloc, not in Berkeley `text` |
| `.bss` | 420,744 | `0x200000c8` | **yes** — zeroed by crt0 |
| `.uninit` | 1,024 | `0x20066c50` | yes |
| `.defmt` | 32 | `0x00000000` | non-alloc, not in Berkeley `text` |
| `.comment` | 228 | `0x00000000` | non-alloc, not in Berkeley `text` |
| `.ARM.attributes` | 48 | `0x00000000` | non-alloc, not in Berkeley `text` |
<!-- END measured ELF sections -->

Berkeley `text` = 766,460 (`.text`) + 18,716 (`.rodata`) + 276
(`.vector_table`) + 20 (`.start_block`) + 32,768 (`.secure_partition`) + 196
(`.data`, which Berkeley classifies as code because the ELF gives the section
the `X` flag) = **818,436**. That identity is stated so a reader can check
the two tables against each other rather than take the sum on trust.

<!-- BEGIN measured ELF summary (check_size_report.py) -->
**Rust device `text` = 818,436 B** · **`.data` = 196 B** · **`.bss` = 421,768 B** · **`.uninit` = 1,024 B**

**RAM statics = 421,964 B** (421,968 B address-to-address: `__sheap` `0x20067050` − RAM origin `0x20000000`). `_stack_start` `0x20082000`, `_stack_end` `0x20067050` → **main stack zone = 110,512 B** of 532,480 B of SRAM.

`bss + stack zone + .data = 532,476 B` against 532,480 B of RAM, leaving 4 B of alignment slack: **there is no unallocated SRAM.** Every byte is a static or the stack, so the only thing that catches a regression is the linker refusing to place `.bss` — and the ceiling that turns that from a link error into a dark board is the one this gate enforces.
<!-- END measured ELF summary -->

### What this fix cost, against the US-1011/US-1012 tip

| figure | US-1011/US-1012 | US-1005/1006 fix (I-1) | delta | US-1007 fix | delta | 2026-09-29 clock fix | delta | US-1020 presence | delta | US-1030 OATH seal | delta |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Berkeley `text` | 808,688 | 808,792 | **+104** | 809,288 | **+496** | 809,448 | **+160** | 809,608 | **+160** | **810,904** | **+1,296** |
| `.text` | 757,128 | 757,176 | +48 | 757,672 | +496 | 757,768 | +96 | 757,928 | +160 | 759,120 | +1,192 |
| `.rodata` | 18,300 | 18,356 | +56 | 18,356 | 0 | 18,420 | +64 | 18,420 | **0** | 18,524 | +104 |
| Berkeley `bss` | 420,336 | 420,336 | 0 | 420,336 | 0 | 420,336 | **0** | 420,380 | **+44** | 420,476 | **+96** |
| RAM statics | 420,532 | 420,532 | 0 | 420,532 | 0 | 420,532 | **0** | 420,576 | **+44** | 421,500 | **+924** |
| main stack zone | 111,944 | 111,944 | 0 | 111,944 | 0 | 111,944 | **0** | 111,900 | **−44** | 111,804 | **−96** |
| **worst call chain** | **92,704** | **92,712** | **+8** | 92,712 | **0** | 92,712 | **0** | **92,712** | **0** | **92,712** | **0** |
| chain headroom (98,304 ceiling) | 5,600 | 5,592 | −8 | 5,592 | 0 | **5,592** | **0** | 5,592 | 0 | **5,592** | **0** |
| second-worst root | 91,964 | 91,964 | 0 | 91,964 | 0 | 91,964 | 0 | 91,964 | 0 | 91,964 | **0** |
| async task frame | 15,744 | 15,744 | 0 | 15,744 | 0 | 15,744 | 0 | 15,744 | 0 | 15,744 | **0** |
| task arena demand | 17,768 | 17,768 | 0 | 17,768 | 0 | 17,768 | 0 | **17,768** | **0** (stamp re-measured) | 17,768 | **0** (stamp re-measured) |
| UF2 blocks | 3,034 | 3,035 | +1 | 3,037 | +2 | 3,037 | **0** | 3,038 | **+1** | 3,038 | **0** (not rebuilt) |

**+160 B of `text` for making the wait's clock a checked precondition, and
not one byte of it on the stack.** The liveness branch in
`TrngProbe::await_ready` and the `ClockReady` proof path in
`Rp2350Timer::require_advancing` are `.text`; the `ClockStalled` format
string is `.rodata`. `.bss` and the RAM statics did not move, so this is
code, not an allocation; the call chain did not move, so no boot-root future
grew. The 740 B of slack between the worst and second-worst chain roots that
the 2026-09-28 header flagged is **untouched** — the constraint that was
worth warning about is still exactly where it was.

**+104 B of `text` for closing an unbounded-wait hole.** The routing itself
is free — `boot_oath` was already generic one layer down, so making its
*signature* generic and passing `&mut *drbg` adds no code. The cost is the
second half of the fix: the boot sanity draw moved from
`trng.random_bytes` to `seed_probe.probe_bytes`, which pulls
`TrngProbe::await_ready`'s deadline loop and `Rp2350Probe`'s
`start`/`stop`/`soft_reset` register sequence into the boot path for the
first time. That is 48 B of `.text` and 56 B of `.rodata` (the `fatal_boot`
string).

**+8 B of stack, and it is the number to watch.** The bounded wait adds a
frame on the boot path that the unbounded call did not have. 8 B out of the
748 B the review flagged as the effective slack between the two task chains
is cheap, and the measurement is the point: had it been 800 B, this fix would
have needed a different shape (a caller with the deadline inlined, or the
draw left on the driver and *recorded* as D-12 rather than fixed).

**The task arena's demand did not move; its stamp did.** No spawned future
changed size — the fix is entirely inside `main`, before any `#[task]` is
spawned. But `check_boot_chain.py`'s stamp covers the firmware's whole
dependency closure, and `main.rs` is in it, so the gate correctly refused to
publish a headroom figure from a stale stamp. `measure_task_arena.py` was
re-run: **17,768 B, unchanged**, stamp `3d66a3a3…` → `339175d3…`. This is
the gate refusing to launder a stale number, working as designed.

### What US-1011 + US-1012 cost, against US-1010

| figure | US-1010 | US-1011/US-1012 | delta |
|---|---:|---:|---:|
| Berkeley `text` | 808,732 | 808,688 | **−44** |
| `.text` | 757,164 | 757,128 | −36 |
| `.rodata` | 18,308 | 18,300 | −8 |
| Berkeley `bss` | 420,328 | 420,336 | **+8** |
| RAM statics | 420,524 | 420,532 | +8 |
| main stack zone | 111,952 | 111,944 | −8 |
| **worst call chain** | **91,956** | **92,704** | **+748** |
| chain headroom (98,304 ceiling) | 6,348 | **5,600** | −748 |
| async task frame | 15,736 | 15,744 | +8 |
| task arena demand | 17,768 | 17,768 | 0 |
| UF2 blocks | 3,034 | 3,034 | 0 |

The flash side **shrank** — the counter's batch window deleted a
whole-keystore rewrite from the per-assertion path, and the code the two
stories added (a window counter, a `note_durable_write` helper, a slack
parameter and its decoder arm) is smaller than what it removed. The one
`.bss` cost is the `Decode` enum discriminant. The **stack** side grew by
748 B: US-1012's first cut did `let mut ks = Self::from_cbor(...)?` and then
mutated it, which put a **second** 12-KiB `DeviceKeystore` on the stack
(`load`'s frame went to 57,204 B and the worst chain to 106,048 B, over the
98,304 B ceiling — `check_boot_chain.py` rejected it). Folding the slack into
the decoder (`decode(bytes, key, Decode::Restore)`, `#[inline(never)]`)
builds the value once, in place, and that is the 748 B this story does cost.

Named statics, unchanged in size by these stories (so the +8 B is new state,
not a resize of an existing buffer):

```
2003faf4 00008004 b ...embassy_executor7__export5ARENA...          # 32,772
20047c8c 0000c000 b ...fapico2_platform8rsa_heap8RSA_HEAP...        # 49,152
200004cc 00000004 b ...fapico2_firmware4boot10AUTH_STORE...        #      4
2001e68c 000000f0 b ...fapico2_firmware4boot7OTP_APP...            #    240
103f0000 00008000 b ...fapico2_firmware4boot16SECURE_PARTITION...  # 32,768 (flash!)
```

The embedded PICOBIN partition-table block sits at `0x100bd900` in this
image (`firmware/uf2gen.py` reports it on every run; US-413 S-413-2).

Gate sweep at this commit:

```text
$ python3 tests/scripts/check_size_report.py
PASS: check_size_report (US-392) — text=808792 bss=420336 uf2=3035 blocks

$ python3 tests/scripts/check_boot_chain.py
PASS: check_boot_chain (US-957) — worst call chain 92712 B <= 98304 B
  (main stack zone 111944 B, 98304 B chain ceiling)
  - boot chain (task poll roots, `bl`/`blx <label>` edges only): 92712 B
  - request-serving chain (App vtable roots + the 15744 B task frame
    the invisible `blx rN` hides): 92712 B
  - margin: 19232 B of the 111944 B main stack zone (17.2 %)
  - per-root chains: 92712 B, 91964 B, 91952 B, 81136 B, 18468 B, 18468 B
  - task arena: demand 17768 B fits ARENA 32772 B (1.84x, floor 1.25x;
    measurement stamp 339175d335a96522… verified against the current sources)

$ python3 tests/scripts/check_async_frame.py
PASS: check_async_frame (US-951) — async-task frame 15744 B <= 24576 B
  (main stack zone 111944 B, 24 KiB absolute ceiling 24576 B)
  - per-task-poll frames: 15744 B, 13544 B, 136 B, 136 B, 44 B, 40 B

$ python3 tests/scripts/check_rng_path.py
RESULT: PASS (one-randomness-path gate green)

$ python3 tests/scripts/check_erase_budget.py
PASS: check_erase_budget (US-1010) — 8 sector erasures per persist across
  8 distinct sectors, 1 per sector, ceiling 100000 assertions (per-sector model)

$ python3 tests/scripts/check_persist_gate.py
RESULT: PASS (273 .rs files scanned, no code-level occurrence)
```

### The headroom that is thinner than it looks

`check_boot_chain.py`'s own summary line is reassuring — 19,240 B of the
111,944 B main stack zone remains, 17.2 % — and that is the *wrong* number to
plan against. The gate constrains the **chain**, not the zone:

* worst chain **92,712 B** against the **98,304 B** ceiling — **5,592 B** left;
* second root **91,964 B**, only **748 B** below the worst.

The two task chains move together, so a change that grows one has effectively
748 B of slack before the gate is at risk, not 5,592 B. US-1012 spent 748 B of
that and this fix spent a further 8 B. The next story that enlarges any future
on this path must
re-measure with `python3 tests/scripts/measure_task_arena.py` (needs nightly)
and re-run the chain gate — the task-arena stamp is verified against the
sources on every gate run, so a changed future is caught rather than assumed,
but the *number* has to be refreshed for the budget to mean anything.

---

## Per-story delta table — CRYPTO-COMPLETION, US-938 … US-950 (US-951 audit)

Every row was measured by US-951 from source (`cargo build --release
--target thumbv8m.main-none-eabi` + `arm-none-eabi-size` + `firmware/uf2gen.py`)
at that commit — none is inherited from the story that made the change. Rows
are in **branch order** (parent → child), which is *not* story-number order:
four of the thirteen stories landed a follow-up fix commit later in the
sequence, so the KDF-DO revert (US-947's fix) sits between US-950's landing
and US-948's fix. That is why `text` is not monotonic in the table.

| # | story | commit | text (B) | Δtext | bss (B) | Δbss | UF2 blocks | UF2 sha256 (first 12) |
|---:|---|---|---:|---:|---:|---:|---:|---|
| — | epic base | `19b0390` | 459,336 | — | 314,696 | — | 1670 | `f003ce71fc17` |
| 1 | US-938 land S-724 RSA + secp256k1 | `7fb66b4` | 750,924 | +291,588 | 445,968 | +131,272 | 2809 | `a6ddf045c422` |
| 2 | US-939 FidoApp → static slot | `495fc05` | 748,520 | −2,404 | 461,688 | +15,720 | 2799 | `beaa20238675` |
| 3 | US-940 RSA PSO:SIGN e2e | `3161fd4` | 748,520 | 0 | 461,688 | 0 | 2799 | `beaa20238675` |
| 4 | US-941 RSA PSO:DECIPHER e2e | `d87862d` | 748,520 | 0 | 461,688 | 0 | 2799 | `beaa20238675` |
| 5 | US-942 RSA-4096 heap | `653371c` | 748,520 | 0 | 461,688 | 0 | 2799 | `beaa20238675` |
| 6 | US-943 RSA nibble gate | `d6ee21f` | 748,508 | −12 | 461,688 | 0 | 2799 | `c3a2fd2a996a` |
| 7 | US-944 Brainpool backend | `baafb9d` | 1,006,920 | +258,412 | 461,688 | 0 | 3809 | `035a81b75b7f` |
| 8 | US-945 Brainpool defaults | `3bafd88` | 1,006,944 | +24 | 461,688 | 0 | 3809 | `b0ba1043fadf` |
| 9 | US-946 Brainpool e2e | `2aea028` | 1,006,944 | 0 | 461,688 | 0 | 3809 | `b0ba1043fadf` |
| 10 | US-947 KDF-DO in PSO:DECIPHER | `31fdfd0` | 1,008,520 | +1,576 | 461,688 | 0 | 3815 | `36672e93e083` |
| 11 | US-948 KDF-DO storage contract | `ef07c2c` | 1,008,520 | 0 | 461,688 | 0 | 3815 | `36672e93e083` |
| 12 | US-949 secp256k1 prehashed + AUT | `ad764fa` | 1,008,760 | +240 | 461,688 | 0 | 3816 | `75eb793bcee8` |
| 13 | US-950 FA honesty + AES roundtrip | `7a24d92` | 1,008,816 | +56 | 461,688 | 0 | 3816 | `afd5c1701a91` |
| 14 | US-949 fix (clippy + virt AUT) | `c123e41` | 1,008,816 | 0 | 461,688 | 0 | 3816 | `afd5c1701a91` |
| 15 | US-947 fix (raw-Z revert) | `6832e81` | 1,007,440 | −1,376 | 461,688 | 0 | 3811 | `12485f16d63e` |
| 16 | US-948 fix (evidence provenance) | `0562403` | 1,007,440 | 0 | 461,688 | 0 | 3811 | `12485f16d63e` |
| 17 | US-950 fix (P-521 caveat) | `46c49cd` | 1,007,440 | 0 | 461,688 | 0 | 3811 | `12485f16d63e` |
| 18 | US-950 fix (FA pin) | `7c1d346` | 1,007,440 | 0 | 461,688 | 0 | 3811 | `12485f16d63e` |
| 19 | US-951 report sweep | `c821b80` | 1,007,440 | 0 | 461,688 | 0 | 3811 | `12485f16d63e` |
| 20 | US-951 fix (RAM-FS stores → `.bss`) | `22f417d` | 941,916 | −65,524 | 527,224 | +65,536 | 3555 | `6b8f8761c0dc` |
| 21 | US-956/US-957 right-size RAM + cut the boot chain | `ae7b780` | 941,520 | **−396** | **412,536** | **−114,688** | **3553** | `fbaca7acce8f` |
| 22 | US-959 X25519 `0x40` format tag | `e51ddb6` | 941,344 | **−176** | **412,528** | **−8** | **3552** | `27af263b6222` |
| 23 | US-962 honesty: restore the keyless-RSA scrub + couple advertise/serve | `83d7164` | **941,452** | **+108** | **412,528** | **0** | **3553** | `21e57a7c5a51` |
| 24 | US-964: the guard that guards, the scrub residual, the arena constant | `ff7b4e8` | 941,444 | −8 | 412,528 | 0 | 3553 | `50e89b94b9a6` |
| 25 | **US-966: defer Brainpool P-384r1 to a follow-up release (P-256r1 kept)** — **tip** | this commit | **775,388** | **−166,056** | **412,528** | **0** | **2904** | `b639432c0a2e` |

**Net epic delta (`19b0390` → this commit): text +482,116 B · bss +97,832 B ·
UF2 +1,883 blocks** — and, after US-956/US-957, the RAM side has a
**35,300 B margin** (`check_boot_chain.py` on this build, after US-961 made
that gate measure the request-serving path again) instead of a 112,772 B
deficit.

| 21 | US-956 right-size RAM + cut the boot chain | US-956 tip | 941,520 | −396 | 412,536 | −114,688 | 3553 | `fbaca7acce8f` |
| 22 | size-report re-baseline (PICOForge-COMPAT tip `653b462`, Phases A–C) | `653b462` | 948,188 | +6,668 | 412,584 | +48 | 3579 | `cb698d323d0b` |
| 23 | size-report re-baseline (PICOForge-COMPAT tip `35f39ab`, Phases D+E) | `35f39ab` | 949,196 | +1,008 | 412,704 | +120 | 3583 | `141b12ace2fc` |
| 24 | size-report re-baseline (factory-wipe `otp.slots.v1` delete) | `e1c95be` | 949,232 | +36 | 412,704 | 0 | 3583 | `7ed2027290da` |
| 25 | size-report re-baseline (US-160 vendor LED applet) | `4181968` | 949,700 | +468 | 412,724 | +20 | 3585 | `8b1283c83577` |
| 26 | size-report re-baseline (US-161/162/163 Rescue applet) | `b95412c` | 951,468 | +1,768 | 412,796 | +72 | 3592 | `6a13c4ac8cf7` |
| 27 | size-report re-baseline (US-170…US-175, Phase I) | `cc3eb8c` | 973,356 | +21,888 | 415,804 | +3,008 | 3678 | `14b72129994f` |
| 28 | size-report re-baseline (ChaCha20-Poly1305 collapse) | `04d1c71` | 968,428 | −4,928 | 415,804 | 0 | 3658 | `4d85ddcf3f03` |
| 29 | **size-report re-baseline (US-181 command chaining)** — **tip** | US-181 tip | **969,364** | **+936** | **419,940** | **+4,136** | **3662 blocks** | `ebb35f2d9d3f` |

**Net epic delta (`19b0390` → US-161/162/163 tip): text +492,132 B ·
bss +98,100 B · UF2 +1,922 blocks** — and, after US-956/US-957 and the
2026-09-27 re-baselines, the RAM side has a **53,084 B margin** instead of a
112,772 B deficit. (Rows 1–23 are the US-951/US-956/Phases-A–C/Phases-D–E
measurement history and are left as measured at the time; row 26 is the current
tip.)


Reading the table:

- **bss never moves after US-939 … until US-956.** Every story from US-940 to
  US-951 is device-code-neutral on the RAM side; the +15,720 B that US-939's
  `boot::FIDO_APP` static slot added (measured: 0x3d6c = 15,724 B) is the last
  *growth* in the epic, and US-956 is the first *reduction* (−114,688 B:
  `RSA_HEAP` −81,920 B, embassy `ARENA` −32,768 B).
- **US-938 dominates the text budget** (+291,588 B): the vendored
  software-RSA stack (`rsa` + `num-bigint_dig` + `crypto_bigint`) plus the
  `trussed-rsa-alloc` service, the RSA key heap's init path and the
  secp256k1 backend.
- **US-944 is the single largest jump** (+258,412 B, +34 % of the image): two
  generic prime-field curve stacks (bp256/bp384 over RustCrypto
  `elliptic-curve` 0.14 / `ecdsa` 0.17) plus the `sha2` 0.11 line they ride.
- **US-940/941/942/946/948/949-fix/950-fix×2 are 0-byte device stories**
  (host-only test and doc work) — confirmed by measurement, not assumed.
  Their UF2 shas are byte-identical to the preceding row, which is the
  strongest form of that claim.
- The `+1,576` / `+240` / `+56` KDF/FA entries and the `−1,376` revert are
  the four US-947…US-950 device deltas; the revert is the largest single
  *negative* text step in the epic.

## Drift audit (US-951)

This document accumulated drift across the epic. US-951 re-derived each
entry; four were stale and are corrected here. The headline `text`/`bss`
block was **not** stale (it matched a from-source rebuild of the tip).

1. **`.secure_partition` size — corrected 0x6000 → 0x8000 (32 KiB).** The
   US-939 section said the NOLOAD reservation was "unchanged at 0x6000
   (24 KiB)". The linked ELF says `.secure_partition 32768` at `0x103f0000`
   (readelf), i.e. 32 KiB. The 24 KiB figure dates from DARK-BOOT-1 and
   had been carried forward unverified.
2. **RAM stack zone — corrected 70,792 B → 5,056 B (the material one).**
   Every "main-stack zone" figure in this document, and in
   `docs/tasks/us942-rsa4096-heap.md` §4, was computed as
   `532,480 − 461,688 = 70,792 B`. That is wrong: Berkeley `bss` counts only
   `.bss` + `.uninit` and **omits the 65,732 B of initialized `.data`** that
   sits in RAM below them. See "RP2350 flash/RAM budget" below for the
   link-map derivation and the consequences.
3. **"Size gate: current `text` = 748,520 B" — corrected to 1,007,440 B.**
   A leftover in the Phase C section that still quoted the US-939 image.
4. **Comparison-table row "Rust `fapico2` current image … 441,816 B" —
   corrected to 1,007,440 B** (0.47× the C baseline, 27.4 % of the ceiling),
   with the historical 441,816 / 0.83× figure kept as the label of what it
   measured (the US-715 final image).

The two US-950 review notes about drift (the "+240 that no story
re-measured") are superseded by the table above: the `+240` is **US-949's**
landing delta (`ef07c2c` → `ad764fa`), measured. The US-950 `+56` is the
`ad764fa` → `7a24d92` step, also as recorded there.

US-947 correction context (2026-09-26): PSO:DECIPHER ECDH returns the **raw**
shared point again. The card stores the KDF-DO and serves it back byte-exact,
but it does not derive with it — gpg derives the key-encryption key in
software from the raw shared point and the KDF parameter blob carried in the
*public key* (`g10/ecdh.c` `extract_secret_x` + `derive_kek`), so a card
that also derived would double-derive. Deltas vs the US-950 landing: text
1,008,816 → 1,007,440 (**−1,376** — the SHA-256/SHA-512 block-KDF
(`kdf::derive`/`derive_with`) plus the decipher hook, and the `sha2` 0.10
dependency leaving opcard entirely; the KDF-DO *parser* and the PUT DATA F9
validation gate stay), bss unchanged at 461,688. Shipping
`firmware/fapico2.uf2`: sha256
`12485f16d63e827c6467be375703aa6903c32b6f14ca2872679e6166ef6f4629`,
3811 blocks (1 absolute preamble + 3810 ARM_S payload) — regenerated from
this exact release build via `python3 firmware/uf2gen.py …`.

US-950 context (2026-09-26): `GET DATA FA`
(`vendor/opcard/src/command/data.rs::algo_info`) now skips any enumerated
algorithm outside `AllowedAlgorithms::allowed_generation`, so the card no
longer advertises algorithms it would refuse with 6A80. Deltas vs the
`ad764fa` (US-949) landing: text 1,008,760 → 1,008,816 (**+56** — three
`is_allowed` + `continue` guards inside one function, LTO-folded; no new
dependency, no new data), bss unchanged at 461,688. The US-950 test work
(`apps/openpgp/tests/dispatch.rs`, `apps/openpgp/tests/device_pso.rs`) is
host-only dev-dependency code and contributes nothing to the device image.
Shipping `firmware/fapico2.uf2`: sha256
`afd5c1701a9139fcb1f1864f3ef631688bf61d0e45ee618f7c22f8dcd306fe2b`,
3816 blocks (1 absolute preamble + 3815 ARM_S payload).

**Drift correction (2026-09-26, US-950).** The measurement block above was
last refreshed at the US-947 landing and read `1,008,520`, but
`check_size_report.py` was *already* failing on the clean `ad764fa` tree:
that commit measures 1,008,760, a **+240** drift from US-948/US-949 that no
story re-measured. The figure above is the true `ad764fa` + US-950
measurement; the intervening +240 belongs to those two stories, not to this
one. US-950's own contribution is the +56 quoted above.

The same drift made the **CI UF2-staleness gate** red on the clean
`ad764fa` tree: the committed `firmware/fapico2.uf2` no longer matched a
build of that commit. US-950 regenerates it
(`python3 firmware/uf2gen.py target/thumbv8m.main-none-eabi/release/
fapico2-firmware firmware/fapico2.uf2`), so both the size report and the
flashable artifact are current as of this commit.

US-947 context (2026-09-26, **superseded by the correction above**): the
KDF-DO structure/derivation module (`vendor/opcard/src/command/kdf.rs` —
parse + SHA-256/SHA-512 block KDF), the PUT DATA F9 validation gate and a
decipher-time application of the KDF landed together. Deltas vs the US-945
landing: text 1,006,944 → 1,008,520 (+1,576 — the KDF parser plus the sha2
0.10 hash cores reaching the LTO cut; the decipher hook itself was small),
bss unchanged at 461,688. That on-card derivation is gone: the KDF-DO is
stored and served so the host can read the parameters and derive, which is
what gpg expects (the correction above re-measures the image at 1,007,440).

US-945 context (2026-09-26): `BRAINPOOL_P256R1` and `BRAINPOOL_P384R1`
joined `AllowedAlgorithms::default_gen()`/`default_import()` (behind
opcard's `brainpool-backend` feature; `BRAINPOOL_P512R1` deliberately
absent — see `docs/known-gate-divergences.md` US-944/US-945). Deltas
vs the US-944 landing (re-measured in that session): text 1,006,920 →
1,006,944 (+24 — two extra bitflag entries in the default-set folds, no
new code paths; the Brainpool request/backend machinery itself landed in
US-944), bss unchanged at 461,688. Shipping `firmware/fapico2.uf2`: sha256
`b0ba1043fadf10bc435cee2226a8e9541dad583f73f0566bf17f88bdd5fb08ce`,
3809 blocks — regenerated from this exact release build via
`python3 firmware/uf2gen.py …`.

US-944 context (2026-09-26): the software Brainpool backend
(`vendor/trussed-brainpool`, bp256/bp384 over the RustCrypto
elliptic-curve 0.14 / ecdsa 0.17 line, dispatched through the platform
`OpcardDispatch` and the opcard virt path) is wired in default-on. Deltas
vs the US-943 landing (re-measured in that session): text 748,508 →
1,006,920 (+258,412 — two full generic prime-field curve stacks
(fiat-crypto field arithmetic + primeorder point arithmetic + RFC6979
ECDSA machinery, instantiated once per curve) plus the sha2 0.11 line the
bp* crates ride; bss unchanged at 461,688 — the backend is allocation-free
and stack-only). Shipping `firmware/fapico2.uf2` (US-944 measurement):
sha256
`035a81b75b7ff0a770cbbbe04da09445feaf1ccb6a7864d20ad944c2347d6bdb`,
3809 blocks — regenerated from that exact release build via
`python3 firmware/uf2gen.py …` (superseded by the US-945 measurement
above).

US-943 context (2026-09-26): the RSA algorithm-attribute parse now accepts
only the standard import-format spellings (nibbles 00/01) — CRT (02/03) and
out-of-spec values fail the parse and PUT DATA answers 6A80
(`docs/tasks/us943-rsa-nibble.md`). Deltas vs the US-939 landing
(re-measured in that session): text 748,520 → 748,508 (−12 — the CRT
attribute constants were replaced by the nibble-01 standard-with-n
constants; net code shrink), bss unchanged at 461,688. Shipping
`firmware/fapico2.uf2` (US-943 measurement): sha256
`c3a2fd2a996a09467f6d0a82caf584498bbbc4463b87a412614f4c1b89bf9c8a`,
2799 blocks — regenerated from that exact release build via
`python3 firmware/uf2gen.py …` (superseded by the US-944 measurement above).

US-939 context (2026-09-26): the Embassy async-main task frame reserved
95,232 B against the main stack — the dark-boot stack overflow. The fix moved
`FidoApp` (15,724 B) into a `boot::FIDO_APP` static slot and constructs the
~98 KiB `MigrationAuthority` field-by-field directly into its `PIN_AUTHORITY`
slot; both measurements and the full analysis live in
`docs/tasks/us939-async-frame-fix.md`. Deltas vs the US-938 landing
(re-measured at `7fb66b4` in this session): text 750,924 → 748,520 (−2,404 —
the app/boot wrappers no longer inline into the async task), bss 445,968 →
461,688 (+15,720 = the `boot::FIDO_APP` slot, 15,724 B; the authority's
`PIN_AUTHORITY` bss reservation is unchanged — it was already sized by the
`MaybeUninit` static before this story). NOTE: the 441,816 B entry below was
the US-715/POLISH-PUB image and was left stale by the US-938 S-724
RSA/secp256k1 landing (vendored software-RSA stack: text → 750,924, UF2 →
1,438,208 B) — this section re-measures and supersedes it.

`.secure_partition` measured at 0x8000 (32 KiB NOLOAD reservation) in the
US-939 image — corrected by US-951; the "0x6000 / 24 KiB" this line carried
since DARK-BOOT-1 was stale (the DARK-BOOT-1 text below is left as written).
Shipping
`firmware/fapico2.uf2`: sha256
`beaa20238675fabc0708040d4c9726d178e5fde17850b49ca2252229cf6e2317`,
2799 blocks — regenerated from this exact release build via
`python3 firmware/uf2gen.py …`.

US-715 (2026-09-21, POLISH-PUB Phase B): the partition image is now walked
in bounded windows everywhere — snapshot (`StoreImageSource` /
`partition_image_window`), validate/restore
(`partition_image_len_reader` / `from_partition_image_reader` over the
volatile `SecureSlotReader`), slot compare (`image_eq_reader`), and program
(`write_windowed`) — so the three `PARTITION_IMAGE_MAX`-sized whole-image
statics are gone: `boot::BOOT_PARTITION_BUF`, `boot::BOOT_SHADOW_BUF` and
`platform::persist::IMAGE_SCRATCH` (2 × 9,100 B + 9,100 B). Measured both
ends, stash-diffed against the pre-reclaim HEAD build under the same
toolchain:

```
HEAD  (pre-US-715)   text 432,672   bss 337,316
work  (post-reclaim, 16-entry)  text 433,588   bss 310,020
work  (final, 24-entry + BOOTSEL fix) text 441,736 bss 314,532
true delta vs HEAD (16-entry baseline)  +9,064 text   −22,784 bss
```

The bss drop (−27,296 B ≈ 27.0 KiB) is the three image statics (−27,300 B
nominal, ±4 B allocation rounding) — ~12 secure-store entries of headroom at
the observed 2.27 KiB/entry cost. The +916 B text is the windowed
walk/reader code. Consequence for the US-715 capacity work: a future
`DEV_MAX_ENTRIES` raise now moves bss by the store static alone (~9.1 KiB
per +16 entries) instead of ~27.3 KiB per step; the MSPLIM/stack constraint
from DARK-BOOT-1 (below) still applies — capacity raises stay
hardware-verified per step, no blind bumps.

DARK-BOOT-1 (2026-09-19, S-731-2; historical — the three image statics it
accounts for no longer exist): the 32-entry store variant (sha
`eb05f992…`, text 443,840 / bss 373,300) was **built and rejected** — it
dark-boots on hardware: the +36,288 B bss growth moved `MSPLIM` (laid out
at the bss end) up by exactly that delta and shrank the main stack region
~127 KiB → ~85 KiB; the boot path overflows it (STKOF) → dark lockup. The
shipping build reverts `DEV_MAX_ENTRIES` to 16 (bss back to 337,012, the
24 KiB `.secure_partition` reservation back) while keeping the round-2/3
fix layers: transactional growth mutations + counter bumps, and the
self-cleaning `write_chunked` — the +292 B text over the round-1 image
(427,164 → 427,456) is exactly that kept fix code.

SOAK-FINDING-1 review round 2 (2026-09-19, S-731-2, superseded by
DARK-BOOT-1): the `DEV_MAX_ENTRIES` 16→32 bump measured text 443,840 /
bss 373,300 — of which the NOLOAD `.secure_partition` reservation grew
24 → 40 KiB (+16,384, accounted in `text` but not flashed); bss +36,288 B
attributed symbol-exactly: three `PARTITION_IMAGE_MAX`-sized image buffers
9,100 → 18,188 B each (`boot::BOOT_PARTITION_BUF`, `boot::BOOT_SHADOW_BUF`,
`platform::persist::IMAGE_SCRATCH`, +27,264) plus the device store static
`boot::STORE` with `[Slot; 32]` (+9,024).

SOAK-FINDING-1 round 1 (2026-09-19, S-731-2): the FIDO keystore capacity +
durable-ack latch fix (transactional capacity in `store_credential_checked`
/ `grow_checked`, the store bound into the HID command path, and the
`stored` fast-path in `persist_if_dirty`) grew text +504 B over the
S-723-A3 candidate (426,660 → 427,164); bss unchanged at 337,012.

The S-722 completion candidate includes three-key/profile restoration,
source-bound profile evidence and the fixed-buffer persistence seam on top
of `7ca3502`. Text grew 4,024 B over S-722-C1 (422,456 B); bss remains
337,004 B. (S-723-A2, 2026-09-19: the 61XX/GET-RESPONSE reply-sizing fix grew
text +104 B and bss +8 B over the S-722 candidate — 426,584 / 337,012.
S-723-A3, 2026-09-19: the fail-closed algorithm-attribute gate grew text
+76 B — 426,660 / 337,012 — measured and regenerated above.) This measurement is not hardware acceptance.

The previous 222,120 B text growth vs the S-721-1 image (171,664 B) is the vendored
opcard stack (OpenPGP command surface + trussed service + littlefs2 C
backend + 64 KiB store statics) that S-721-1 compiled into the platform
rlib but LTO-elided — nothing referenced `trusted_backend` from the
firmware root yet. S-721-2 calls `DeviceBackend::boot` from `main` and
serves the real OpenPGP app, so the stack is now linked. The 13,312 B bss
growth is the trusted-backend RAM stores (external/volatile littlefs2
buffers) entering the link the same way.

Note on accounting: the `text` column includes the NOLOAD
`.secure_partition` section (reserved address space in the 64 KiB secure
region, not part of the UF2 payload). The per-section and per-crate
breakdowns below remain the 2026-09-11 (post-US-413) measurement's
(llvm-nm lower bounds — the US-430 pass reconciled the baseline numbers,
not the per-crate breakdown).

## Phase C delta vs measured baseline (US-430, 2026-09-14)

Both ends measured, not inherited (`arm-none-eabi-size`; each ELF rebuilt
from its own commit — base `31212da` in a throwaway worktree, HEAD
`570fab6` in-tree):

```
commit                  text     data    bss
31212da  (Phase C base) 170,760      0  216,136
570fab6  (Phase C HEAD) 171,336      0  225,232
true delta                 +576      0   +9,096
```

The bss growth is US-427's second boot slot buffer
(`BOOT_SHADOW_BUF`, one `SECURE_PARTITION_SIZE` =
`PARTITION_IMAGE_MAX` static in `firmware/src/boot.rs`); the text growth
is the remaining US-427/US-429 boot-decision + gate plumbing. US-430's
own changes are doc-comment-only: every loadable ELF section
(`.text`, `.rodata`, `.data`, `.vector_table`, `.start_block`,
`.secure_partition`) is byte-identical before/after, and the committed
UF2 sha is unchanged (`516fd79c…`).

**Stale-baseline note (US-427 review adjudication, re-verified by
US-430):** the 74,308 B `text` figure this doc carried from the v1.0.0-era
(post-US-413) measurement is STALE — the US-427 reviewer corroborated it
against the base artifacts (the base UF2 was 569 blocks while the doc
claimed 198). All delta claims in this doc now use the measured `31212da`
baseline above, not 74,308 B.

Size gate: current `text` = 775,388 B (2026-09-27 US-966 image
`b639432c0a2e…`) < ceiling 3,670,016 B (headroom 2,894,628 B — 79 % free).
(Historical: US-964 941,444 B; US-962 941,452 B; US-959 941,344 B; US-956
941,520 B; US-951 fix 941,916 B; US-950 landing 1,008,816 B; US-939

Size gate: current `text` = 949,232 B (2026-09-27 re-baseline at `e1c95be`,
image `7ed2027290da…`) < ceiling 3,670,016 B (headroom 2,720,784 B — 74 % free).
(Historical: Phases D+E `35f39ab` 949,196 B; US-956 941,520 B; US-951 fix 941,916 B; US-950 landing 1,008,816 B; US-939

748,520 B; US-938 landing 750,924 B; DARK-BOOT-1 427,456 B; S-723-A3
426,660 B.)

US-939 also adds the async-frame gate `tests/scripts/check_async_frame.py`:
it rebuilds the ELF, measures the Embassy async-main task frame from the
disassembly and fails while it exceeds `min(24 KiB, the real stack zone)`
(pre-fix: 95,232 B; post-US-939: 18,288 B; post-US-956: 9,216 B). Wired into
the CI `device-build` job next to the size gate.

US-956 adds `tests/scripts/check_boot_chain.py` (see "Main-stack demand") —
the frame gate alone could not have caught the 63,000 B `FidoApp::boot`
frame.

## C baseline (re-measured, same tool)

`pico-fido2/build_pico2/pico_fido2.elf`:

```
   text	   data	    bss	    dec	    hex
 530980	      0	  86804	 617784	  96d38	pico_fido2.elf
```

**C baseline text = 530,980 B** (re-measured — not the stale US-382
inherited number).

| Firmware | text (B) | vs C | % of ceiling |
|---|---:|---:|---:|
| C `pico-fido2` (all apps + PIV) | 530,980 | 1.00× | 14.5 % |
| **Rust `fapico2` current image (US-966)** | **775,388** | **1.46×** | **21.1 %** |
| *historical:* Rust `fapico2` (US-715 final + POLISH-PUB review) | *441,816* | *0.83×* | *12.0 %* |

The Rust image is **1.46× the C baseline** (775,388 / 530,980). It crossed
the C firmware during this epic and stayed above it through US-966.

> **⚠ 2026-09-27 (US-966).** The 1.77× / 941,344 B / 25.7 % figures in the
> original text of this section, and the "2,728,672 B (74 %) free" headroom
> below it, are **historical**. The peak was real — it was the image with
> **two** generic prime-field Brainpool curve stacks, and US-944's +258,412 B
> is the growth that produced it. US-966 removed the P-384r1 stack
> (−166,056 B), which is **64 % of US-944's addition**; the remaining ~36 % is
> the P-256r1 stack, which stays. So the honest reading of US-944's row is
> not "the Brainpool backend cost 258 KB" but "**P-384r1 alone cost 166 KB
> of it, and P-256r1 — the curve that works on hardware — costs the rest**."

The trade itself is deliberate and unchanged: the C firmware is served by a
compact per-app C surface, while the Rust image carries the full opcard
OpenPGP command surface, a software-RSA stack, secp256k1 and one generic
prime-field Brainpool curve stack, all at `opt-level = "z"` / fat LTO. The
budget matters more than the ratio, and the 3,670,016 B ceiling now leaves
**2,894,628 B (79 % free)**. (Historical: post-US-427 the image was 171,336 B /

| **Rust `fapico2` current image (`e1c95be`)** | **949,232** | **1.79×** | **25.9 %** |
| *historical:* Rust `fapico2` (Phases D+E, `35f39ab`) | *949,196* | *1.79×* | *25.9 %* |
| *historical:* Rust `fapico2` (Phases A–C, `653b462`) | *948,188* | *1.79×* | *25.8 %* |
| *historical:* Rust `fapico2` (US-956 tip) | *941,520* | *1.77×* | *25.7 %* |
| *historical:* Rust `fapico2` (US-715 final + POLISH-PUB review) | *441,816* | *0.83×* | *12.0 %* |

The current Rust image is **1.79× the C baseline** (949,232 / 530,980) —
it crossed the C firmware during this epic, and US-944 alone accounts for
+258,412 B of the +507,416 B of growth over the US-715 image. That is a
deliberate trade, not an accident: the C firmware is served by a compact
per-app C surface, while the Rust image carries the full opcard OpenPGP
command surface, a software-RSA stack, secp256k1 and two generic prime-field
Brainpool curve stacks, all at `opt-level = "z"` / fat LTO. The budget
matters more than the ratio, and the 3,670,016 B ceiling still leaves
2,720,784 B (74 %) free. (Historical: post-US-956 941,520 B / 1.77×;
post-US-427 the image was 171,336 B /

0.32×; post-S-721-1, 171,664 B — the opcard stack was compiled but
LTO-elided until S-721-2 linked it.)

## Flash budget

The RP2350 on the Pico 2 has **4 MiB (4,194,304 B) of NOR flash**:

```
4 MiB total  −  0.5 MiB keystore / headroom  =  3.5 MiB text ceiling
= 4194304 B    −      524288 B                  =  3670016 B
```

**Ceiling: 3,670,016 bytes (3.5 MiB) of `text`** (CI: `7 * 1024 * 1024 / 2`,
integer-only bash arithmetic). Current headroom: **2,894,628 B (79 % free)**
(3,670,016 − 775,388). The US-964 figure was 2,728,672 B (74 %).

integer-only bash arithmetic). Current headroom: **2,720,784 B (74 % free)**
(3,670,016 − 949,232).

Even at the full C-baseline size the firmware uses only ~14.5 % of the
ceiling — the gate turns the build red long before flash is exhausted.

## RP2350 flash / RAM budget (US-951; re-measured US-956; re-measured 2026-09-27)

Both budgets are read off the linked release ELF, not off the Berkeley
summary. **This is the requirement-4 table, and it corrects a number that
this document and `docs/tasks/us942-rsa4096-heap.md` §4 both got wrong by
65,732 B.**

### Flash

| region | bytes | source |
|---|---:|---|
| NOR flash (Pico 2 QSPI) | 4,194,304 | `memory.x` / RP2350 address map |
| − keystore / headroom reserve | −524,288 | size-gate policy (0.5 MiB) |
| **`text` ceiling** | **3,670,016** | CI: `7 * 1024 * 1024 / 2` |
| measured `text` | −941,344 | `arm-none-eabi-size`, post-US-959 |
| **flash headroom** | **2,728,672 (74 % free)** | |

`text` (Berkeley) is the sum of `.vector_table` 276 + `.start_block` 20 +
`.text` 889,380 + `.rodata` 18,704 + `.data` 196 + `.secure_partition`
32,768 = 941,344, and `data` reports 0 because Berkeley folds the

| measured `text` | −949,232 | `arm-none-eabi-size`, `e1c95be` (2026-09-27) |
| **flash headroom** | **2,720,784 (74 % free)** | |

`text` (Berkeley) is the sum of `.vector_table` 276 + `.start_block` 20 +
`.text` 897,052 + `.rodata` 18,920 + `.data` 196 + `.secure_partition`
32,768 = 949,232, and `data` reports 0 because Berkeley folds the

initialized `.data` load image into `text` (the ELF gives `.data` the `X`
flag, so it is classified as code, not data). **That classification was worth
65,536 B of phantom flash usage** while the two RAM stores sat in `.data`;
the US-951 fix moved them to `.bss`, so the `text` gate no longer charges
flash for 64 KiB of RAM. US-956 touches `.text` by −396 B (the in-place
`FidoApp`/`OathApp` constructors plus the two new `#[inline(never)]` walls).

| UF2 artifact | value |
|---|---:|
| `firmware/fapico2.uf2` | 1,486,848 B = 2,904 × 512 |
| — preamble block (absolute address family) | 1 × 512 B |
| — ARM_S payload blocks | 2,903 × 512 B |
| — of which embedded PICOBIN partition-table block | 180 B at `0x100b5600` |

The US-956 UF2 was 3,555 → 3,553 blocks (−1,024 B) — the `#[inline(never)]`
walls and the in-place constructors. (The much larger US-951 step, 3,811 →
3,555, was the `.data` move: −65,536 B of flash no longer being copied at
boot, `0x100ee100` → `0x100de100`.) **US-959: 3,553 → 3,552 blocks** —
codegen churn around the `decrypt_ec` point-format test, not a designed
change. **US-962: 3,552 → 3,553 blocks** — the restored scrub's load-time
branch and conditional save. **US-964: 3,553 → 3,553 blocks** — the scrub's
`sign_count == 0` clause came out (−8 B of `.text`, inside the last partial
block). **US-966: 3,553 → 2,904 blocks (−649, −332,288 B)** — by a wide
margin the largest UF2 step in the epic, and the only one driven by a
designed *removal* rather than by a fix: the Brainpool P-384r1 flash-resident
curve stack (see "The measured per-crate attribution" above). Note the block
delta is twice the `text` delta in *bytes of file* because the UF2 frame
carries 256 B of flash per 512 B block; 649 × 256 = 166,144 B of flash,
which is the `text` + `rodata` delta (166,056 B) up to block alignment.
The shipping artifact is **2904 blocks**,
1,486,848 bytes. sha256
`b639432c0a2ea0662e7468aa8fc08476e49994aee1b8b349034a0355bc36ad51`
(US-964 tip: `50e89b94b9a63cc26e74cc077f4c68db4d125841a7adefb0c64cd3e2435febff`)
(US-959 tip: `27af263b6222f89d62ece6f3b0bf3225d9c2ab56fb603c55adb2f8859f3a8f37`)
(US-956 tip: `fbaca7acce8fdb5b8e5c8ebc56a93740f19b0f5d0a6b96cf88bfcf462214b83f`).

| `firmware/fapico2.uf2` | 1,834,496 B = 3,583 × 512 |
| — preamble block (absolute address family) | 1 × 512 B |
| — ARM_S payload blocks | 3,582 × 512 B |
| — of which embedded PICOBIN partition-table block | 180 B at `0x100dfd00` |

**The shipping UF2 was stale and has been regenerated.** The committed
`firmware/fapico2.uf2` at `653b462` was still the US-956 artifact
(`fbaca7acce8f…`, 3,553 blocks) and did **not** match a build of the tip
(`cmp` against a fresh `firmware/uf2gen.py` run differed at byte 537). The
2026-09-27 re-baseline regenerates it from the release ELF that was measured
above — 3,553 → 3,579 blocks (+13,312 B) — and records the new sha256
`cb698d323d0bb5ec2d7939dbaa73d726971af692caf5aedbc47b651745b0c421`.
The embedded partition-table block moved `0x100ddf00` → `0x100df900` with the
`.rodata` growth. (The US-956 UF2 was 3,555 → 3,553 blocks; the much larger
US-951 step, 3,811 → 3,555, was the `.data` move.)

**The UF2 moved once more in the same day's second re-baseline** (Phases D+E,
tip `35f39ab`): 3,579 → 3,583 blocks (+2,048 B) over the OTP/OATH code, sha
`cb698d32…` → `141b12ac…`. The artifact is regenerated from the same release
ELF and is again `cmp`-byte-identical to what the tree carries. The embedded
partition-table block moved `0x100df900` → `0x100dfd00`. Phase D+E is a
feature step, not a measurement correction — the previous re-baseline's
"stale UF2" finding does not recur, for the same reason US-950 → US-951 →
US-956 did not.

**And once more in the same day's third re-baseline** (factory-wipe
`otp.slots.v1` delete, tip `e1c95be`): the artifact was regenerated from the
release ELF measured above, sha `141b12ac…` → `7ed20272…`, with the **block
count and byte length unchanged** at 3,583 blocks / 1,834,496 B — a +36 B
`text` step does not cross a 512 B block boundary. The content moved, so the
sha did, but the size did not; this is the first re-baseline in the epic's
history where the UF2's length is *not* a proxy for the `text` delta, and it
is worth stating so nobody reads the unchanged block count as "nothing
changed". The embedded partition-table block stays at `0x100dfd00`.


### RAM — and the stack-zone correction

`memory.x` maps `RAM : ORIGIN = 0x20000000, LENGTH = 520K` = **532,480 B**.
Berkeley `bss` (527,224 B) counts `.bss` + `.uninit`. Before the US-951 fix
it counted **only** those two and silently omitted 65,732 B of initialized
`.data` that is equally real RAM. Both link maps, for the record:

| region | addr | pre-US-951 | US-951 fix | US-956/US-957 | **US-959 (tip)** |
|---|---|---:|---:|---:|---:|
| `.data` (initialized, copied from flash at boot) | `0x20000000` | 65,732 | 196 | 196 | **196** |
| `.bss` (zeroed) | `0x200000c4` | 460,664 | 526,200 | 411,512 | **411,504** |
| `.uninit` | `0x20064c18` | 1,024 | 1,024 | 1,024 | **1,024** |
| **RAM used (statics)** | | **527,420** | **527,420** | **412,732** | **412,724** |
| `_stack_end` = `__sheap` | | 0x20080c40 | 0x20080c40 | 0x20064c40 | **0x20064c38** |
| **main stack zone** `_stack_end`→`_stack_start` | | **5,056** | **5,056** | **119,744** | **119,752** |
| boot call chain (task poll roots) | | ~117,828 | ~117,828 | 67,288 | **66,184** |
| worst call chain incl. request path | | ~117,828 | ~117,828 | 88,348 (US-957 derivation) | **84,452** (`check_boot_chain.py`, which surcharges the `App` vtable hop) |
| **SRAM margin** | | **−112,772** | **−112,772** | **+31,396** | **+35,300 (29.5 %)** |
| **RAM total** | | **532,480** | **532,480** | **532,480** |

| region | addr | pre-US-951 | US-951 fix | US-956 | **`e1c95be` (tip)** |
|---|---|---:|---:|---:|---:|
| `.data` (initialized, copied from flash at boot) | `0x20000000` | 65,732 | 196 | 196 | **196** |
| `.bss` (zeroed) | `0x200000c8` | 460,664 | 526,200 | 411,512 | **411,680** |
| `.uninit` | `0x200648e8` | 1,024 | 1,024 | 1,024 | **1,024** |
| **RAM used (statics)** | | **527,420** | **527,420** | **412,732** | **412,900** |
| `_stack_end` = `__sheap` | | 0x20080c40 | 0x20080c40 | 0x20064c40 | **0x20064ce8** |
| **main stack zone** `_stack_end`→`_stack_start` | | **5,056** | **5,056** | **119,744** | **119,576** |
| boot call chain (task poll roots) | | ~117,828 | ~117,828 | 67,288 | **66,392** |
| worst call chain incl. request path | | ~117,828 | ~117,828 | 88,348 | **66,392** |
| **SRAM margin** | | **−112,772** | **−112,772** | **+31,396** | **+53,184** |
| **RAM total** | | **532,480** | **532,480** | **532,480** | **532,480** |


**`.data` is RAM.** Berkeley `bss` counts `.bss` + `.uninit` and *omits* the
initialized `.data`, which is equally real RAM; that omission is what hid
65,732 B and produced the wrong "70,792 B stack zone" figure. Every RAM
number above is `.data` + `.bss` + `.uninit` from `arm-none-eabi-size -A`,
never Berkeley `bss` alone.

Symbols: `_stack_start = 0x20082000` (cortex-m-rt `link.x`:
`PROVIDE(_stack_start = _ram_end)`), `_stack_end = __sheap`
(`link.x`: `PROVIDE(_stack_end = .)` after `.uninit`). The stack grows down
from RAM top, so the usable main stack is exactly `_stack_start − _stack_end`
— 5,056 B at the US-951 tip (**0.9 % of the part, which is why the device
could not boot**), 119,744 B after US-956, **119,576 B at `35f39ab`**.

> **⚠ The 70,792 B figure previously quoted here and in
> `docs/tasks/us942-rsa4096-heap.md` §4 is wrong by 65,732 B.** It was
> computed as `532,480 − 461,688`, which silently omits `.data`. The two
> 32 KiB statics that were in `.data` are
> `fapico2_platform::trusted_backend::device::VFS_STORAGE` and
> `EFS_STORAGE` (`platform/src/trusted_backend/device.rs`, `RamFsStorage`,
> introduced by US-331) — the littlefs2 RAM backing stores for the OpenPGP
> app. They were const-initialized to the erase value 0xFF, not to zero, so
> rustc put them in `.data` (loaded from flash at boot) rather than `.bss`.
>
> **Consequence, stated plainly: bss + stack zone does *not* fit with
> margin — it fits with a 5,056 B (0.9 %) stack zone, and the US-939
> async-main frame reservation of 18,176 B is 3.6× that zone.** The
> post-US-939 arithmetic is: `bss` grew +15,720 B (`boot::FIDO_APP`, 0x3d6c =
> 15,724 B measured), which moved `_stack_end` up by the same amount; the
> pre-US-939 stack zone was 20,776 B. US-939 cut the frame from 95,232 B to
> 18,176 B, which is a large improvement but still exceeds what is left.
>
> **US-951 resolution (2026-09-26).** US-951 landed the `.data`→`.bss` move
> (both stores are now `MaybeUninit`, written once in
> `DeviceFsStore::boot` / `mount_ram_fs` before any task exists — the same
> discipline as every sibling static in that file). It is **RAM-neutral and
> buys no stack**: `.data` 65,732 → 196 B, `.bss` 460,664 → 526,200 B, total
> RAM and `_stack_end` unchanged. The "~69 KiB" prediction above was wrong,
> and the pre-US-939 figure of 20,776 B was wrong for the same
> `.data`-is-not-RAM reason. See "Main-stack demand" for what the real
> requirement is — it is larger still.
>
> **US-956 resolution (2026-09-26) — both remaining directions were on
> the table, and the second one is the one that worked.** Option 1 (a
> dedicated stack / a heap) was not taken: the whole problem is a *RAM
> budget* problem, and a second stack would have to come out of the same
> 532,480 B. Option 2 (shrink the frames) is what landed —
> `FidoApp::boot_in_place` / `OathApp::boot_in_place` construct straight into
> the app statics (the `#[inline(never)]` + static-slot treatment US-939
> applied to `FidoApp`, now applied to the two boot functions US-939 missed),
> and it is gated by `check_boot_chain.py` so it cannot regress. Option 3
> (`DEV_MAX_ENTRIES`) was left alone: it can only ever *cost* stack.
>
> The full derivation, the two static re-derivations, and the
> statics-that-were-verified-and-*not*-cut are in
> `docs/tasks/us956-ram-right-sizing.md`.

### RSA heap and static slots (US-939 / US-942 / **US-956** deltas)

Addresses and sizes below are from `arm-none-eabi-nm -S` on the **US-956**
release ELF. **Re-measured 2026-09-27 at `35f39ab`: the US-956 sizes are
unchanged except where Phase D+E is noted below; only the addresses moved**
(+0x78 for the statics below `.bss`'s start, following the +168 B of `.bss`
growth). The "bytes" column below is the 2026-09-27 re-measurement.

| item | symbol | addr | bytes | Δ this epic |
|---|---|---|---:|---|
| software-RSA heap (**US-956**) | `rsa_heap::RSA_HEAP` | `0x20045f5c` | **49,152** | **−81,920 bss** — 128 KiB → 48 KiB, re-derived from the measured worst RSA peak (see below) |
| RSA allocator wrapper | `rsa_heap::RSA_ALLOC` | `0x20064808` | 28 | 0 |
| Embassy task arena (**US-956**) | `embassy_executor::_export::ARENA` | `0x2003ddc4` | **32,772** | **−32,768 bss** — 64 KiB → 32 KiB, 1.85x the measured six-task demand |
| FIDO app slot (**US-939**) | `boot::FIDO_APP` | `0x2001d650` | 15,764 | **+15,720 bss** (nominal 15,724; ±4 B rounding) — moved out of the async frame; US-956 made the *boot* build it in place; +32 B in Phase D+E |
| OATH app slot (pre-existing) | `boot::OATH_APP` | `0x2003b1b8` | 11,272 | 0 (US-956: same in-place treatment); +8 B in Phase D+E |
| OTP app slot (**Phase D+E, new**) | `boot::OTP_APP` | `0x2001d560` | 240 | **+240 bss** — the Yubico OTP applet (4 slots, STATUS TLVs, touch gate) |
| OTP auth store (**Phase D+E, new**) | `boot::AUTH_STORE` | `0x200004cc` | 4 | **+4 bss** — access-code material for the OTP applet |
| migration authority slot (pre-existing) | `boot::PIN_AUTHORITY` | `0x20001ec8` | 98,404 | 0 — **verified inherent** (§ below), not cut |
| migration buffers (pre-existing) | `boot::MIG_BUFS` | `0x200231a4` | 98,324 | 0 — **verified inherent** (§ below), not cut |
| secure store (hardware-verified) | `boot::STORE` | `0x2001a054` | 13,580 | 0 — `DEV_MAX_ENTRIES = 16` is the DARK-BOOT-1 hardware ceiling |
| management app slot (pre-existing) | `boot::MANAGEMENT_APP` | `0x20019f2c` | 296 | 0 |
| OpenPGP RAM-FS stores | `VFS_STORAGE` / `EFS_STORAGE` | `0x20059f5c` / `0x20051f5c` | 65,536 (2 × 32,768) | **+65,536 bss, −65,536 `.data`** (US-951) — RAM-neutral; littlefs2 capacity, inherent |
| secure-partition slots | `boot::SECURE_PARTITION` | **`0x103f0000`** | 32,768 | 0 — **flash, not RAM** (see below) |

#### RSA heap: 128 KiB → 48 KiB, re-derived from measurement

The US-942 note ("all inside 128 KiB with ~90 % margin") compared the
**keygen** peak against the heap — and the keygen peak is not the worst RSA
operation. Re-measured with the same peak-instrumented host mirror
(`apps/openpgp/tests/rsa_heap_peak.rs`, max of 3 runs each, full card flow,
window = exactly the span in which `SoftwareRsa.request` allocates):

| operation | measured peak (B) | at a 49,152 B heap |
|---|---:|---|
| RSA-2048 GENERATE | 7,018 | 7.00x headroom |
| RSA-3072 GENERATE | 13,034 | 3.77x |
| RSA-4096 GENERATE | 13,160 / 13,162 | 3.73x |
| **RSA-4096 PSO:SIGN (worst case)** | **24,792** | **1.98x** |
| ambient control (GET DATA) | 256 | — |

The peaks are **byte-identical across repeats at every size** — structural in
the modulus width, not a data-dependent prime-search draw.

**Why not 13,162 B (a 1.0x bound on the keygen peak).** The `rsa` /
`num-bigint-dig` stack grows with **infallible** `Vec` allocations: an
exhausted heap does not return an error, `handle_alloc_error` **aborts the
process** (`panic = "abort"`). A 1.0x bound is a coin flip on a
structural-but-unmeasured variation, and the failure costs a device. The
1.98x multiplier is chosen to absorb **one further `Vec` doubling rung** in the
sign path — the realistic tail, since a single buffer crossing a power-of-two
boundary is the only thing in this stack that can move the peak. The
`rsa4096_generated_key_signs_verifiably` test now asserts that headroom floor
(≥1.5x) explicitly, so a future regression fails on a *bound* with an
actionable message rather than only on the abort.

The host mirror of `RSA_HEAP_SIZE` (the module is `#[cfg(target_arch =
"arm")]`-only) is pinned to the device source by
`device_heap_mirror_matches_rsa_heap_rs`.

#### The ~98 KiB pair that was verified and *not* cut

`boot::PIN_AUTHORITY` (98,404) and `boot::MIG_BUFS` (98,324) are each one
`MigrationBuffers` (16 KiB `scratch` + 5 × `heapless::Vec<u8, 16 KiB>`), and
the 196 KiB total is **inherent, not over-reservation**:

- `scratch` is where `chunked::read_chunked` puts the *entire* captured C
  OpenPGP keystream; a capture over 16 KiB already fails today.
- each per-class `HVec` is handed to `store.write`, which rejects anything
  over `MAX_VALUE_LEN` = 16 KiB — so a smaller vector would turn a migration
  that succeeds today into a `SlotOverflow` failure. That is a behaviour
  change, and US-956 is a memory-placement story.

The duplicate *is* real. The obvious dedup — pointing the authority at the
firmware's `MIG_BUFS` — was **rejected**: it makes two live `&mut` alias one
`static mut`, exactly the discipline US-939 established and US-956 must
preserve. The sound version (a shared `&'static RefCell<MigrationBuffers>`)
is a design change to a platform type shared with the host backend and 50
migration tests, and it is recorded as follow-up work in the story doc.

#### Embassy task arena: 64 KiB → 32 KiB, re-derived from measurement

The arena is a fixed-size reservoir embassy bump-allocates one
`TaskPool<F, 1>` per spawned task into; overflow **panics "task arena is
full"** at the first spawn that does not fit — a dark boot, and one nothing in
the suite measures. Demand measured with

```
RUSTFLAGS=-Zprint-type-sizes cargo +nightly build --release --target thumbv8m.main-none-eabi
```

| task | `TaskPool<F, 1>` |
|---|---:|
| `tasks::ccid_task` | 8,600 |
| `tasks::hid_task` | 8,136 |
| `usb_task` | 736 |
| `__embassy_main` | 160 |
| `led_heartbeat_task` | 56 |
| `button_poll_task` | 56 |
| **total demand** | **17,744** |

**32,768 B = 1.85x** the demand (was 3.7x). 46 KiB of a 532,480 B part was
being spent on a reservoir that is 84 % empty. The demand is carried in
`fapico2_firmware::TASK_ARENA_DEMAND_B` and gated by `check_boot_chain.py`
(fails if it stops fitting, or below 1.25x headroom).

#### `boot::SECURE_PARTITION` is not RAM

`nm` prints it in the `b` (bss) class because it is NOLOAD, but it is
`#[link_section = ".secure_partition"]` at **`0x103f0000`** — inside NOR
flash — and `arm-none-eabi-size -A` charges its 32,768 B to the `text` column.
It is address space, not SRAM. It has never been part of any RAM total in this
document.

### Main-stack demand (US-951 measured; **US-956 resolved; US-957 corrected; US-961 re-measured**)

### Main-stack demand (US-951 measured; **US-956 resolved; US-957 corrected; re-measured 2026-09-27**)


`check_async_frame.py` bounds one frame. The **main stack has to survive a
whole call chain**, because every Embassy task, the trussed runner, and every
interrupt handler share the single MSP stack. The chain is measured by
building a call graph from the release disassembly (`bl`/`blx` edges between
known functions; `b.w` tail calls are not edges — they reuse the caller's
frame; `blx rN` is **not** an edge either, which is what US-957 had to
account for), folding each function's prologue frame reservation (`push {…}` +
`sub.w sp, sp, #N` + `sub sp, #N`), condensing recursion with Tarjan's SCC,
and taking the longest path over the condensation. `tests/scripts/
check_boot_chain.py` automates exactly this.

| task poll | own frame (US-951) | own frame (US-956) | chain (US-951) | chain (US-956) | **chain (`35f39ab`)** |
|---|---:|---:|---:|---:|---:|
| **`#[main]` (boot path)** | 18,288 B | 9,216 B | 117,796 – 117,828 B | 67,288 B | **66,392 B** |
| CCID/HID serve loop | 9,840 B | 9,840 B | 51,100 – 51,148 B | 51,148 B | *no longer a separate root* |
| third task | 144 B | 144 B | 1,336 B | 1,336 B | **3,140 B** |
| remaining three | 40–144 B | 40–144 B | 160 – 300 B | 160 – 300 B | **16 B / 8 B** |
| **`App` vtable roots** (US-957; entered by an invisible `blx rN`, so charged with the deepest task frame stacked on top) | — | — | — | 78,508 B + 9,840 B = 88,348 B | **66,392 B** (gate's `chain(App-impl root) + 9,208 B task frame`; lands equal to the boot root, so it is not the binding root today) |

Boot-path chain, before → after (deepest branch):

```
 US-951                                          US-956
 18,288  TaskStorage::<__embassy_main>::poll     9,216  TaskStorage::<__embassy_main>::poll
 15,744  boot_fido                                  16  boot_fido
 63,000  FidoApp::boot                          24,880  FidoApp::boot_in_place
 19,440  DeviceKeystore::persist               32,000  DeviceKeystore::load
   ~120   aes / defmt / panic leaves               ...  aes / defmt / panic leaves
────────                                     ────────
117,828  vs a 5,056 B zone — 23.3x over        67,288  vs a 119,744 B zone — 56 % used
```

That last "56 % used" is the **boot** chain only. The worst chain on the part
is the request-serving one — **84,452 B, 70.5 % of the 119,752 B zone used,
35,300 B (29.5 %) of margin** — for the reason given next.

That last "56 % used" is the **boot** chain only. At the US-956 tip the worst
chain on the part was the request-serving one at 88,348 B — **73.8 % used,
31,396 B (26.2 %) of margin** — for the reason given next. **Re-measured
2026-09-27 at `35f39ab`, the gate's worst root is 66,392 B against a 119,576 B
zone — 55.5 % used, 53,184 B (44.5 %) of margin**; at this tip the request
root no longer exceeds the boot root, so the two coincide. See the caveat in
"Re-baseline 2026-09-27" about which root wins.


(The min/max pair US-951 reported is the SCC weighting: summing a recursion
cycle's members over-counts it, taking only the largest under-counts it. The
three cycles — `core::slice::sort::quicksort`, `core::panicking`, and defmt's
acquire/write pair — are all small, so the bound is tight.)

**What changed and why.** US-939 moved `FidoApp` into a static slot but left
the *value flowing through the stack*: `boot_fido` still reserved 15,744 B for
the `Result<FidoApp, _>` sret destination and memcpy'd it into the slot, and
`FidoApp::boot` reserved a second 15,724 B `Self` for the fresh-partition arm.
US-956 adds `FidoApp::boot_in_place` / `OathApp::boot_in_place` (and
`OathApp::new_in_place`), which write each field straight into the slot, and
walls `attestation::provision` and `DeviceKeystore::load` with
`#[inline(never)]` so the restore arm stops paying for the fresh arm's ~32 KiB
of inlined P-256 scratch. `FidoApp::boot` / `OathApp::boot` remain as thin
by-value wrappers *over* the in-place constructors, so the host and emulation
suites run the same construction and cannot diverge.

**The result: the device is no longer RAM-starved.** 412,724 B of statics +
84,452 B of worst-case chain = 497,176 B of 532,480 B, i.e. **35,300 B
(29.5 % of the stack zone) of margin.** See "The request-serving path US-956
could not see" below for why the worst chain is not the 66,184 B boot chain.
(US-956 originally reported this line as 412,732 + 88,348 = 31,396 B of
margin; US-957 corrected the 88,348 B, and US-961 re-measured both figures on
the tip ELF with the repaired gate. The statics and the boot chain did not
move — only the *worst* chain's measurement, because for ~30 commits the
gate was not taking it.)

**The result: the device is no longer RAM-starved.** At the US-956 tip:
412,732 B of statics + 88,348 B of worst-case chain = 501,080 B of 532,480 B,
i.e. **31,396 B (26.2 % of the stack zone) of margin.** Re-measured
2026-09-27 at `35f39ab`: **412,900 B + 66,392 B = 479,292 B of 532,480 B,
i.e. 53,184 B (44.5 %) of margin.** (The exact margin is
`119,576 − 66,392 = 53,184 B`; `532,480 − 479,292 = 53,188 B` differs by the
4 B of alignment padding between the end of `.data` and the start of `.bss` at
`0x200000c8` — the same 4 B the US-956 paragraph above carried.) See "The request-serving path US-956
could not see" below for why the US-956 figure was 88,348 B and not the
67,288 B that story originally reported.


### The request-serving path US-956 could not see (US-957)

The 67,288 B figure above is the **boot** chain: the longest path from an
Embassy `TaskStorage::<F>::poll` root along `bl` / `blx <label>` edges. It is
real, but it is **not the worst chain on the part**, and the reason is a blind
spot in the edge model rather than a number that moved.

`platform/src/dispatch.rs` holds the registered apps as
`Vec<&'a mut dyn App, N>` and reaches them through the vtable, so the
per-APDU `App::process` call is a **register-indirect `blx rN`**, not a `bl`.
`check_boot_chain.py` parsed only `bl`/`blx <label>`, and there are **1,115
`blx rN` sites in this release ELF** — none of them edges. The boot path
reaches `FidoApp::boot_in_place` and friends by *static* dispatch, so it was
fully visible; the request path was not. And the request path is where all of
this epic's crypto lives: RSA (keygen, PSO:SIGN/DECIPHER, PUT KEY import),
secp256k1 and Brainpool are all reached per APDU, none of it on the boot path.

The chain the gate could not see, rooted at the `App` trait impls
(`<OpenPgpApp<T> as App>::process`, 64 B own frame):

```
    64  <OpenPgpApp<T> as App>::process          platform/src/dispatch.rs
  ...  OpenPgpApp::run / card.handle
11,488  opcard::Command::exec
  ...  the mechanism dispatch
 6,688  CryptoClient::decrypt  (→ trussed-rsa-alloc → rsa/num-bigint-dig)
  ...  BigUint / Vec working set
──────
78,508  the App-impl chain, standalone
+9,840  the CCID/HID polling task's own frame (the frame the invisible
        `blx rN` sits in — the gate cannot follow the edge, so it charges
        the deepest possible caller frame on top)
──────
88,348  the true worst case
```

**How the gate accounts for it.** `tests/scripts/check_boot_chain.py`
(US-957) takes a **second root class**: every
`fapico2_platform::dispatch::App` trait impl — `process`, `select`,
`select_apdu`, `deselect`, `factory_wipe` — becomes a root, and a vtable
root is charged `chain(root) + max own frame over the task-poll roots`. That
is a deterministic upper bound on `task poll frame + … + vtable callee
chain`, and it needs no dataflow analysis: the point is that the gate must
not report green at the boot chain while the real chain crosses 96 KiB. The
gate also *prints* the `blx rN` site count, so the remaining indirect blind
spots stay visible instead of silent.

**US-961: the second root class was, in fact, not being taken.** Both gates
selected their roots with rustc *legacy* mangling fragments, and the toolchain
now emits **v0**. Measured on this exact release ELF: the legacy patterns
matched **4** "task roots" (not the 6 in the binary) and **0** of the 18
`dispatch::App` vtable shims — the class described in the paragraph above did
not exist at run time. The gate still printed
`PASS: worst call chain 66184 B … 44.7 % margin` and exited 0, because the
only evidence was in a `--json` field (`"vtable_root_count": 0`) that CI does
not read, and CI had never run on this branch. The same blindness hit
`check_async_frame.py`, which reported a 9,208 B max frame while `hid_task`
alone reserves **9,928 B**.

US-961's fix, in `tests/scripts/stack_roots.py` (shared by both gates, so
they cannot drift into measuring different things again):

* match on **mangling-independent identifiers** — `dispatch` / `App` /
  `process`, `embassy_executor` / `raw` / `TaskStorage` / `poll` — never on a
  crate name, because v0 path compression legitimately drops
  `fapico2_platform` from the symbol;
* **floor the root set against source** and hard-fail on any shortfall: the
  task roots must equal the number of `#[task]` / `#[main]` declarations in
  the device binary's own module tree (`firmware/src/main.rs` + its `mod`
  tree), and the `App::process` roots must be at least the number of apps
  `apps/src/registry.rs` registers. A floor that cannot be derived is itself
  a FAIL.

Re-measured on this ELF, the gate now sees all 6 task polls, 18 vtable shims
(4 of them `App::process`), and reports:

```
PASS: check_boot_chain (US-957) — worst call chain 84452 B <= 98304 B (main stack zone 119752 B, 98304 B chain ceiling)
  - boot chain (task poll roots, `bl`/`blx <label>` edges only): 66184 B
  - request-serving chain (App vtable roots + the 9928 B task frame the invisible `blx rN` hides): 84452 B
  - margin: 35300 B of the 119752 B main stack zone (29.5 %)
  - roots measured: 6 Embassy task poll(s) (floor 6, …) + 18 `dispatch::App` vtable shim(s),
    of which 4 are `App::process` (floor 4, …). A shortfall in any of these is a FAIL, not a note.
```

The verdict survives, and the honest margin is **35,300 B (29.5 %)** — between
US-956's boot-only 52,456 B (43.8 %) and US-957's hand-derived 31,396 B
(26.2 %). The 84,452 B is 3,896 B under US-957's 88,348 B derivation: codegen
movement since (US-959, and a newer rustc than the one that produced it), not
a change of method. Both differences are reporting corrections, not memory
regressions — nothing grew.

The US-957 verdict survives and widens — at `35f39ab` the gate's worst
chain is 66,392 B against a 119,576 B zone, a **53,184 B (44.5 %)** margin.
(At the US-956 tip the same verdict was **88,348 B in a 119,744 B zone =
31,396 B (26.2 %)**, not the 52,456 B (43.8 %) US-956 reported — that
difference was entirely a reporting defect, not a memory regression.)
The **1,115 `blx rN` sites quoted above are the US-956 count; the 2026-09-27
build has 1,163**, so the indirect blind spots have grown and US-957's
reasoning is unchanged.


**What is still not proven:** the whole analysis is linker arithmetic and
host measurement. Nothing here shows the part boots — that is US-952. See
`docs/tasks/us956-ram-right-sizing.md` §8 for the full list of what needs
hardware. `rust-toolchain.toml` still pins `channel = "stable"` unpinned, so
a toolchain bump can change codegen; US-961's defence against that is the
fail-loud floor, not a pin, so a bump that *changes what the gates see* is a
red build rather than a silently narrower measurement.

## CI gate (US-382)

The `device-build` job in `.github/workflows/ci.yml` measures `text` on the
release ELF and **hard-fails if `text > 3,670,016 B`**; `arm-none-eabi-size`
`bss` must fit the 520 K RAM map in `firmware/memory.x` (412,704 B — within
the map; was 412,584 B at the `653b462` re-baseline and 412,536 B at the
US-956 tip). Note the CI check uses Berkeley `bss`, which by itself does **not**
prove the stack zone is viable: `.data` is RAM and is charged to `text`, and
the zone is whatever the linker leaves after `.uninit`. The repo gates that
*do* close that:

- `tests/scripts/check_size_report.py` (US-392) — rebuilds the ELF and fails
  if this document disagrees with the measurement.
- `tests/scripts/check_async_frame.py` (US-939/US-951; **US-961 repaired**) —
  **stack-zone aware**: reads `_stack_start` and `_stack_end` from the ELF and
  bounds the frame by `min(24 KiB, stack zone)` instead of a hard-coded
  24,576 B. The old ceiling was *larger than the entire stack the linker
  leaves*, so it could not fail, and a 3.6x overflow sat behind a green gate.
  **Verified correct in US-956 and left as is.** It read
  `FAIL … async-task frame 18288 B > limit 5056 B` at the US-951 tip and reads
  `PASS … 9928 B <= 24576 B (main stack zone 119752 B)` now (the max over all
  six task polls; the boot poll itself is 9,208 B). The 9,208 → 9,928 change is
  US-961: before it, `hid_task` was not a measured root at all, so the gate
  was reporting the second-largest frame as the largest.
- `tests/scripts/check_boot_chain.py` (**US-956, new; US-957 extended; US-961
  repaired**) — the

  `PASS … 9208 B <= 24576 B (main stack zone 119576 B)` now (the max over
  all task polls, re-measured 2026-09-27; at the US-956 tip it read
  `PASS … 9840 B <= 24576 B (main stack zone 119744 B)`, and the boot poll
  itself was 9,216 B).
- `tests/scripts/check_boot_chain.py` (**US-956, new; US-957 extended**) — the

  missing gate. Nothing measured call-chain depth, so a future 63,000 B frame
  would have passed again. It bounds the longest path from any
  `TaskStorage::<F>::poll` **or any `dispatch::App` trait impl** by
  `min(96 KiB, the real stack zone)` and carries the task-arena check. It
  reproduces US-951's 117,828 B on the pre-change ELF and reads 84,452 B now:

```
PASS: check_boot_chain (US-957) — worst call chain 84452 B <= 98304 B (main stack zone 119752 B, 98304 B chain ceiling)
  - boot chain (task poll roots, `bl`/`blx <label>` edges only): 66184 B
  - request-serving chain (App vtable roots + the 9928 B task frame the invisible `blx rN` hides): 84452 B
  - margin: 35300 B of the 119752 B main stack zone (29.5 %)
  - per-root chains: 84452 B, 84448 B, 66184 B, 51180 B, 12652 B, 12652 B
  - roots measured: 6 Embassy task poll(s) (floor 6, …) + 18 `dispatch::App` vtable shim(s),
    of which 4 are `App::process` (floor 4, …). A shortfall in any of these is a FAIL, not a note.
  - 1147 register-indirect `blx rN` call sites in the ELF: not resolved into edges. …
  - task arena: demand 17744 B fits ARENA 32772 B (1.85x, floor 1.25x)
```

- `tests/scripts/stack_roots.py` (**US-961, new**) — the shared root selection
  both stack gates use, and the reason the numbers above can be trusted. It
  matches mangling-independent identifiers and **floors the root set against
  source**, failing hard on any shortfall (see "The request-serving path US-956
  could not see" above). Without it the two gates could again measure
  different things and neither would know.
- `tests/scripts/check_heap_gate.py` (**US-961, new**; replaces the US-383
  `no-heap` token grep) — the device heap is either absent or *exactly* the one
  sanctioned allocator, and nothing may allocate before it goes live. It also
  checks that the heap is actually linked into the release image
  (`rsa-backend` in the platform default features), so the "exactly one
  sanctioned allocator" claim is about the binary and not just the source.

  Both stack gates are wired into the `device-build` CI job by **US-957** —
  before that, `check_boot_chain.py` and `check_size_report.py` were referenced
  by nothing in `.github/`, so a regression in either would have merged. The
  heap gate is the `no-heap` job. **Neither had ever been run on this branch
  until US-961**, which is how a 0-of-18 vtable root set and a red `no-heap`
  job both survived 30 commits.

  reproduces US-951's 117,828 B on the pre-change ELF; it read 88,348 B at the
  US-956 tip and reads **66,392 B** at `35f39ab` (re-measured 2026-09-27):

```
PASS: check_boot_chain (US-957) — worst call chain 66392 B <= 98304 B (main stack zone 119576 B, 98304 B chain ceiling)
  - boot chain (task poll roots, `bl`/`blx <label>` edges only): 66392 B
  - request-serving chain (App vtable roots + the 9208 B task frame the invisible `blx rN` hides): 66392 B
  - margin: 53184 B of the 119576 B main stack zone (44.5 %)
  - per-root chains: 66392 B, 3140 B, 16 B, 8 B
  - 1163 register-indirect `blx rN` call sites in the ELF: not resolved into edges. …
  - task arena: demand 17744 B fits ARENA 32772 B (1.85x, floor 1.25x)
```

(US-956/US-957 output, kept for the record — the two root classes no longer
differ at this tip, and there are four task-poll roots instead of six:
`88348 B <= 98304 B (main stack zone 119744 B)`; boot chain 67,288 B;
per-root `88348, 88344, 67288, 51148, 12560, 12560`; 1,115 `blx rN`.)

  Both gates are wired into the `device-build` CI job by **US-957** — before
  that, `check_boot_chain.py` and `check_size_report.py` were referenced by
  nothing in `.github/`, so a regression in either would have merged.


## Per-crate breakdown (`llvm-nm`, `.text` symbols only, fat-LTO ELF)

**Re-measured by US-951 at the post-epic tip `7c1d346`.** The previous table
in this section was the 2026-09-11 (post-US-413) measurement and described a
48,432 B `.text` section; the real section is **889,380 B** (890,584 B at
`7c1d346`; US-956 moved it by **−396 B** and US-959 by a further **−820 B**,
so the table below is unchanged to within 0.1 % and was not re-derived). Symbol sizes are attributed to the
owning crate by parsing both the demangled and the raw (v0-mangled,
generic-instantiation) symbol views — `llvm-nm --demangle` leaves
`_$LT$ecdsa..signing..SigningKey$LT$C$GT$…` unmangled, so a demangle-only
pass silently drops ~200 KB of curve maths.

Symbols total 889,756 B of the 890,584 B section (99.9 %); the 828 B
difference is alignment padding. The gate number itself is larger than
`.text` — Berkeley `text` also carries `.rodata` 18,704, `.vector_table` 276,
`.start_block` 20, `.data` (196 B now; 65,732 B before the US-951 `.data`→
`.bss` move) and `.secure_partition` 32,768.

| Crate / group | `.text` (B) | share |
|---|---:|---:|
| ~~Brainpool P-384r1 — `p384` + `bp384` (US-944)~~ | ~~175,392~~ | ~~19.7 %~~ — **superseded by US-966, and the row was never one crate** |
| fapico2 first-party crates (fido/openpgp/oath/mgmt/piv/platform/firmware) | 82,920 | 9.3 % |
| trussed P-521 — `p521` | 81,644 | 9.2 % |
| trussed core + service + platform shims | 67,816 | 7.6 % |
| sha2 + sha1 (RSA / Brainpool / CTAP digests) | 52,954 | 5.9 % |
| opcard (vendored OpenPGP card stack) | 32,788 | 3.7 % |
| RSA bigint — `rsa` / `num-bigint-dig` / `crypto-bigint` | 23,834 | 2.7 % |
| Brainpool P-256r1 — `bp256` (US-944) | 21,128 | 2.4 % — **kept by US-966; the only Brainpool curve this build serves** |
| embassy — executor / usb / rp / sync / time | 18,986 | 2.1 % |
| `core` + `compiler_builtins` + `alloc` | 17,536 | 2.0 % |
| curve-generic ECDSA / primeorder / elliptic-curve machinery | 14,560 | 1.6 % |
| secp256k1 — `k256` + US-949 prehashed verify | 12,838 | 1.4 % |
| Ed448 — `ed448-goldilocks` (vendored no_std patch) | 8,072 | 0.9 % |
| trussed P-256 — `p256` | 7,834 | 0.9 % |
| AES + cipher glue | 7,034 | 0.8 % |
| heapless / no-std container glue | 3,612 | 0.4 % |
| generic instantiations whose concrete crate LTO erased + C/LLVM runtime | 260,808 | 29.3 % |
| **total `.text` symbols** | **889,756** | **99.9 %** |

> **⚠ 2026-09-27 (US-966).** The two Brainpool rows above are now wrong in
> opposite directions, and both errors are instructive:
>
> * The **19.7 % / 175,392 B** row is labelled "`p384` + `bp384`", and it was
>   read for months as "Brainpool P-384r1 costs a fifth of the image". It does
>   not. `p384` is the **NIST** P-384 crate — independently advertised, still
>   served by trussed Core, and **not removed by US-966** (measured delta
>   −976 B, i.e. LTO noise). Reading a two-crate row as one curve is what
>   produced the "258 KB" claim.
> * The **2.4 % / 21,128 B** `bp256` row likewise understates the P-256r1
>   cost, for the same reason on the other side: the curve-generic
>   elliptic-curve 0.14 stack that `bp256` instantiated is in the
>   *unattributed* 29.3 % row, not in the 2.4 % row.
>
> After US-966 the per-crate split is the one measured in "The measured
> per-crate attribution" above: `bp384` **0 B**, its SHA-384 half **0 B**,
> `bp256` unchanged.

Two things this table made visible, recorded as they stood at US-964:

- **Curves dominate.** P-384r1 + P-256r1 + P-521 + the curve-generic ECDSA /
  primeorder layer + secp256k1 + sha2/sha1 together were **442,148 B — half
  the `.text` section.** US-944's +258,412 B is entirely in this band; that
  is what "two full generic prime-field curve stacks" cost on RP2350, of
  which US-966 gave back **166,056 B** (64 %) by removing one of the two.
- **The 29.3 % residual is honest, not slack.** It is dominated by v0-mangled
  generic instantiations (`_<T as Trait>::method` forms) whose concrete
  instantiating crate LLVM erased, plus C/LLVM runtime helpers. It is *not*
  attributable per crate by symbol name, and treating it as one bucket is
  more truthful than splitting it by guesswork.

LTO inlines heavily, so every named row is a **lower bound** for that crate.

## Gate sweep (US-956, 2026-09-26; size/frame/chain rows re-run 2026-09-27; **full sweep re-run at `e1c95be`**)

All `check_*.py` in `tests/scripts/`, run at the US-956 tip. US-951 ran
eleven; US-956 retired one and added one, so the count is still eleven. The
three RAM/size rows below were re-run at `35f39ab` on 2026-09-27. **The
factory-wipe re-baseline re-ran the complete sweep of all eleven at `e1c95be`
— every gate exits 0, none regressed** (the `blx rN` count moves 1,163 →
1,164 and `check_persist_gate` now scans 234 `.rs` files, both from the code
the re-baseline measures, neither a failure).

| gate | story | result |
|---|---|---|
| `check_async_frame.py` | US-939 / US-951 | **PASS** — `async-task frame 9840 B <= 24576 B (main stack zone 119744 B)`; per-poll `9840, 9216, 144, 144, 44, 40 B`. Was a true-positive FAIL (18,288 B > 5,056 B) at the US-951 tip |
| `check_attestation_gate.py` | US-916 | **PASS** |
| **`check_boot_chain.py`** | **US-956 (new)** | **PASS** — `worst task call chain 67288 B <= 98304 B (main stack zone 119744 B, 98304 B chain ceiling)`; per-root `67288, 51148, 1336, 300, 212, 208 B`; `task arena: demand 17744 B fits ARENA 32772 B (1.85x, floor 1.25x)` |
| `check_dbg_release_gate.py` | US-922 | **PASS** — all 4 checks |
| `check_debug_strip.py` | S-391-13 | **PASS** — 16 `.rs` files scanned, 0 hits |
| `check_persist_gate.py` | US-429 | **PASS** — 223 `.rs` files scanned |
| `check_readme.py` | US-392 | **PASS** — 236 lines (limit 250) |
| `check_release_notes.py` | US-393 | **PASS** |
| `check_size_report.py` | US-392 | **PASS** — `text=775388 bss=412528 uf2=2904 blocks` (US-966 re-run; the 941,520 row is the US-956 measurement) |
| `check_us413_feasibility.py` | US-413 | **PASS** |
| `check_wrapup.py` | US-392 / US-955 | **PASS** — see note |

| `check_async_frame.py` | US-939 / US-951 | **PASS** — US-956: `async-task frame 9840 B <= 24576 B (main stack zone 119744 B)`; per-poll `9840, 9216, 144, 144, 44, 40 B`. **Re-run 2026-09-27 at `35f39ab`: `async-task frame 9208 B <= 24576 B (main stack zone 119576 B)`; per-poll `9208, 28, 8, 8 B`** (unchanged from the `653b462` re-run except for the 120 B the new statics took off the zone). Was a true-positive FAIL (18,288 B > 5,056 B) at the US-951 tip. **Re-run at `e1c95be`: identical — 9,208 B / 119,576 B zone** (the +36 B is `.text`/`.rodata`, so the zone does not move). **Re-run at the US-161/162/163 Rescue-applet tip: frame 9,216 B against a 119,484 B zone** (the +8 B is the `ccid_task` frame's pending-reboot local; the zone's 48 B of new static is the Rescue applet slot) (the applet's 48 B slot is the only new static) |
| `check_attestation_gate.py` | US-916 | **PASS** — re-run at `e1c95be`, all 4 checks |
| **`check_boot_chain.py`** | **US-956 (new)** | **PASS** — US-956: `worst call chain 67288 B <= 98304 B (main stack zone 119744 B, 98304 B chain ceiling)`; per-root `67288, 51148, 1336, 300, 212, 208 B`; `task arena: demand 17744 B fits ARENA 32772 B (1.85x, floor 1.25x)`. **Re-run 2026-09-27 at `35f39ab`: `worst call chain 66392 B <= 98304 B (main stack zone 119576 B)`; per-root `66392, 3140, 16, 8 B`; arena unchanged. Re-run at `e1c95be`: identical 66,392 B chain and 53,184 B margin; `blx rN` count 1,163 → 1,164. Re-run at the US-161/162/163 Rescue-applet tip: chain unchanged at **66,400 B**, margin **53,084 B** of a 119,484 B zone (44.4 %)** |
| `check_dbg_release_gate.py` | US-922 | **PASS** — all 4 checks; re-run at `e1c95be` |
| `check_debug_strip.py` | S-391-13 | **PASS** — 16 `.rs` files scanned, 0 hits; re-run at `e1c95be` |
| `check_persist_gate.py` | US-429 | **PASS** — 234 `.rs` files scanned at `e1c95be` (was 223 at US-956) |
| `check_readme.py` | US-392 | **PASS** — 236 lines (limit 250); re-run at `e1c95be` |
| `check_release_notes.py` | US-393 | **PASS**; re-run at `e1c95be` |
| `check_size_report.py` | US-392 | **PASS** — US-956: `text=941520 bss=412536 uf2=3553 blocks`. Phases A–C (`653b462`): `text=948188 bss=412584 uf2=3579 blocks`. Re-run 2026-09-27 at `35f39ab`: `text=949196 bss=412704 uf2=3583 blocks`. **At `e1c95be`: `text=949232 bss=412704 uf2=3583 blocks`. At the US-160 vendor-LED tip: `text=949700 bss=412724 uf2=3585 blocks`. At the US-161/162/163 Rescue-applet tip: `text=951468 bss=412796 uf2=3592 blocks`** |
| `check_us413_feasibility.py` | US-413 | **PASS**; re-run at `e1c95be` |
| `check_wrapup.py` | US-392 / US-955 | **PASS** — see note; re-run at `e1c95be` |


### Gate sweep (US-961, 2026-09-27) — after the two gates were repaired

US-961 added `check_heap_gate.py`, so the count is now twelve. The three rows
that changed are the two stack gates and the new one; **every row below was
re-run at the US-961 tip**, and the two stack gates were additionally verified
to *fire* by breaking what they guard (see "Proof the new checks fire" below).

| gate | story | result |
|---|---|---|
| `check_async_frame.py` | US-939 / US-951 / **US-961** | **PASS** — `async-task frame 9928 B <= 24576 B (main stack zone 119752 B)`; per-poll `9928, 9208, 136, 136, 44, 40 B`; `roots measured: 6 of 6 declared tasks`. (The pre-US-961 run said `9840 B` from **4** roots; it was reporting a frame 720 B *smaller* than `hid_task`'s, because `hid_task` was not a root.) |
| `check_boot_chain.py` | US-956 / US-957 / **US-961** | **PASS** — `worst call chain 84452 B <= 98304 B (main stack zone 119752 B, 98304 B chain ceiling)`; per-root `84452, 84448, 66184, 51180, 12652, 12652 B`; `roots measured: 6 task poll(s) (floor 6) + 18 vtable shim(s), 4 of them App::process (floor 4)`; `task arena: demand 17744 B fits ARENA 32772 B (1.85x, floor 1.25x)`. (The pre-US-961 run said `66184 B … 44.7 % margin` from **4** task roots and **0** vtable roots.) |
| **`check_heap_gate.py`** | **US-961 (new; replaces the US-383 `no-heap` grep)** | **PASS** — exactly one sanctioned `#[global_allocator]` (`platform/src/rsa_heap.rs`, a `LockedHeap` over the fixed `RSA_HEAP`); `firmware/src/main.rs` is `#![no_std]`; `rsa-backend` is in the platform default features; `rsa_heap::init()` has exactly one call site, inside `DeviceBackend::boot`, and nothing but non-allocating `assert!`s precedes it |

**Proof the new checks fire (US-961).** A check that has never been observed
red is not a check. Each of these was made to fail deliberately and then
reverted; all are reproducible by re-applying the same edit:

| # | what was broken | result |
|---|---|---|
| A | `stack_roots.TASK_POLL` reverted to the legacy `$LT$..$GT$` form | both stack gates **exit 1**: "the ELF yields 0 task-poll root(s) but the device binary declares 6" |
| B | `stack_roots.TASK_POLL` narrowed to the `#[main]` task only | `check_async_frame` **exit 1**: "2 … but … declares 6" (the partial-shrink case, i.e. the exact pre-US-961 failure) |
| C | a 7th `#[task]` declared in `firmware/src/tasks.rs` | `check_async_frame` **exit 1**: "6 … but … declares 7" — the floor tracks source, not the build |
| D | `stack_roots.APP_SHIM` reverted to the legacy form | `check_boot_chain` **exit 1**: "only 0 `App::process` vtable root(s) for 4 registered CCID app(s)" |
| E | a second `#[global_allocator]` added to `platform/src/rsa_heap.rs` | heap gate **exit 1**: "2 declarations … exactly one is sanctioned" |
| F | the sanctioned allocator **deleted** | heap gate **exit 1**: "no `#[global_allocator]` … the 48 KiB static RSA heap is load-bearing" |
| G | an allocator smuggled into `platform/src/dispatch.rs` | heap gate **exit 1**: "unsanctioned `#[global_allocator]` at platform/src/dispatch.rs:566" (the original US-383 catch still works) |
| H | `DevicePlatform::new(...)` moved **above** `rsa_heap::init()` in `DeviceBackend::boot` | heap gate **exit 1**: "runs code before `rsa_heap::init()`" |
| I | a second `rsa_heap::init()` call site added | heap gate **exit 1**: "called from 2 site(s) … must have exactly one" |
| J | `rsa-backend` dropped from `fapico2-platform`'s default features | heap gate **exit 1**: "the heap is cfg'd out of the device image" |

**`check_boot_ladder.py` is retired (US-956), not repointed.** It required
`docs/tasks/us391-boot-ladder.md`, which was **deliberately deleted** in
`c401a95 docs: slim docs/tasks to decision-grade records (POLISH-PUB)` (a
1,253-line removal, alongside `phase7-ladder.md`). The script was never
retired or repointed when that pass slimmed the docs, so the gate had been red
ever since — it is orphaned, not regressed, and it failed identically on
every commit of the epic (i.e. this was a pre-existing break, not a US-956
regression).

**Why retire rather than repoint at
`docs/tasks/us391-boot-debug-notes.md`.** The gate existed to keep a growing
hardware cycle-log doc honest while cycles were still being appended to it.
The replacement note is an 84-line decision-grade *root-cause* record with a
different structure (Summary / Root Cause / Evidence / The Fix / What Was
Ruled Out / Action Items) — no Baseline, no six-column Cycle log, no Skip log.
Re-pointing the structural gate at it would mean reshaping that note into the
ladder's shape, i.e. resurrecting the deleted content in a new file — which is
precisely the call the POLISH-PUB pass (and the US-956 brief) declined to
make. The decisions the ladder recorded are already carried forward into
`docs/tasks/us391-boot-debug-notes.md` and into this document, so nothing is
lost by dropping the structural gate. No firmware change is involved either
way.

**`check_wrapup.py` PASSes, but it does not cover what US-955 needs.** Its
actual checks are narrow: the `EPIC-merged-firmware.md` pointer notes and
three phrases in `docs/bootsel.md`. It does **not** verify story checkboxes,
epic status, or the one-commit-per-story rule. So US-955's requirements 2
and 3 remain open and untested by any gate: `EPIC-crypto-completion.md`
still reads `**Status:** Draft`, no story checkbox is ticked, and several of
the stories have follow-up fix commits in addition to their primary one. That
is expected-and-deferred to US-955; neither US-951 nor US-956 closed it.

Host suite in the same session:

- `cargo test --workspace --exclude fapico2-firmware --target
  x86_64-unknown-linux-gnu` → **612 passed, 0 failed, 0 ignored** across 74
  test binaries. (US-951: 611 / 65 — the +1 is the new
  `device_heap_mirror_matches_rsa_heap_rs`.) Largest: `rsa_heap_peak` 151,
  `migration_restore` 50, `dispatch` 40, `user_presence` 36,
  `auth_boundary` 26, `device_pso` 18.
- `cargo clippy --workspace --exclude fapico2-firmware --target
  x86_64-unknown-linux-gnu --all-targets -- -D warnings` → **clean, exit 0**.
  The only warnings are `missing_docs` from the out-of-workspace
  `vendor/opcard` path dependency, which `-- -D warnings` does not reach —
  same caveat US-951 recorded.
- `cargo test -p fapico2-openpgp --test rsa_heap_peak … -- --nocapture
  --test-threads=1` → **6 passed, 0 failed** with the **48 KiB limit armed**;
  `US956 MARGIN worst_peak=24792 B device_heap=49152 B headroom=24360 B
  multiplier=1.98x`.

## Reproduction

**2026-09-28 re-measure at the US-1011/US-1012 counter-batching tip — this is
the canonical reproduction for the current numbers.** Toolchain: **stable**
(`rust-toolchain.toml` → `stable`; `rustc 1.98.1 (48a229cea 2026-09-01)`).
The task-arena demand in the gate output below is the one figure that needs
nightly, and it is measured by `tests/scripts/measure_task_arena.py`, which
shells out to `cargo +nightly … -Zprint-type-sizes` itself. It **was** re-run
for this re-measure, because the clock fix touches `firmware/src/main.rs` and
the stamp's fingerprint covers that file: `python3
tests/scripts/measure_task_arena.py` re-measured **6 task pools, 17,768 B
total** — unchanged, which is the point, since the fix adds no future to any
boot root — and rewrote the stamp to `208be613bad6ba87f…`.
`check_boot_chain.py` re-verifies that stamp against the current sources on
every run.

```bash
$ ./build.sh            # cargo build --release --target thumbv8m.main-none-eabi
                        # + python3 firmware/uf2gen.py  (stable)
firmware/fapico2.uf2: 3038 blocks (1 absolute preamble + 3037 ARM_S payload), 1555456 bytes
a5a7459757d716dd637dc43d7fc97e73e98d28474e6d901bcaad569184300b48  firmware/fapico2.uf2

$ python3 firmware/uf2gen.py target/thumbv8m.main-none-eabi/release/fapico2-firmware /tmp/repro.uf2
$ cmp /tmp/repro.uf2 firmware/fapico2.uf2 && echo REPRO
REPRO                                    # byte-identical: the sha256 is reproducible

$ arm-none-eabi-size target/thumbv8m.main-none-eabi/release/fapico2-firmware
   text	   data	    bss	    dec	    hex	filename
 809608	      0	 420380	1229988	  12c4a4	fapico2-firmware

$ arm-none-eabi-size -A target/thumbv8m.main-none-eabi/release/fapico2-firmware
section                size        addr
.secure_partition     32768   272564224     # 0x103f0000 — FLASH, not RAM
.vector_table           276   268435456
.start_block             20   268435732
.text                757928   268435968
.rodata               18420   269194040
.data                  196   536870912     # RAM — Berkeley folds it into `text`
.gnu.sgstubs              0   269212656     # non-alloc, not in Berkeley `text`
.bss                 419312   536871112
.uninit                1024   537290424
# plus non-alloc .defmt 31, .comment 228, .ARM.attributes 48
# RAM statics = 196 + 419312 + 1024 = 420,532

$ arm-none-eabi-nm target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    | grep -E '_stack_(start|end)$|__sheap'
20066ab8 B __sheap
20066ab8 B _stack_end
20082000 A _stack_start        # main stack zone = 0x1B548 = 111,944 B

$ python3 tests/scripts/check_size_report.py
PASS: check_size_report (US-392) — text=808688 bss=420336 uf2=3034 blocks

$ python3 tests/scripts/check_boot_chain.py
PASS: check_boot_chain (US-957) — worst call chain 92704 B <= 98304 B
  (main stack zone 111944 B, 98304 B chain ceiling)
  - boot chain (task poll roots, `bl`/`blx <label>` edges only): 92704 B
  - request-serving chain (App vtable roots + the 15744 B task frame
    the invisible `blx rN` hides): 92704 B
  - margin: 19240 B of the 111944 B main stack zone (17.2 %)
  - per-root chains: 92704 B, 91964 B, 91952 B, 81136 B, 18468 B, 18468 B
  - task arena: demand 17768 B fits ARENA 32772 B (1.84x, floor 1.25x;
    measurement stamp 3d66a3a3d0ffa1ec… verified against the current sources)

$ python3 tests/scripts/check_async_frame.py
PASS: check_async_frame (US-951) — async-task frame 15744 B <= 24576 B
  (main stack zone 111944 B, 24 KiB absolute ceiling 24576 B)

$ python3 tests/scripts/measure_task_arena.py        # nightly, -Zprint-type-sizes
measured 6 task pools, 17,768 B total, stamp 3d66a3a3d0ffa1ec…
  button_poll_task: 56
  ccid_task: 8,600
  embassy_main: 176
  hid_task: 8,144
  led_heartbeat_task: 56
  usb_task: 736
dependency closure: 389 packages
```

**2026-09-27 re-baseline at `e1c95be` (factory-wipe v1 record delete) —
superseded by the entry above.** The same day's
`35f39ab` (Phases D+E) and `653b462` (Phases A–C) notes follow it, then the
US-956 note; all three are kept as history.

```bash
$ cargo build --release --target thumbv8m.main-none-eabi
$ arm-none-eabi-size target/thumbv8m.main-none-eabi/release/fapico2-firmware
   text	   data	    bss	    dec	    hex	filename
 949232	      0	 412704	1361936	  14c810	target/thumbv8m.main-none-eabi/release/fapico2-firmware

$ arm-none-eabi-size -A target/thumbv8m.main-none-eabi/release/fapico2-firmware
section                size        addr
.secure_partition     32768   272564224     # 0x103f0000 — FLASH, not RAM
.vector_table           276   268435456
.start_block             20   268435732
.text                897052   268435968
.rodata                18920   269333024
.data                  196   536870912     # RAM — Berkeley folds it into `text`
.gnu.sgstubs              0   269352160     # non-alloc, not in Berkeley `text`
.bss                 411680   536871112
.uninit                1024   537282792
# plus non-alloc .defmt 27, .comment 228, .ARM.attributes 48
# RAM statics = 196 + 411680 + 1024 = 412,900   (unchanged vs 35f39ab)

$ arm-none-eabi-nm target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    | grep -E '_stack_(start|end)$'
20064ce8 B _stack_end
20082000 A _stack_start        # main stack zone = 0x1D318 = 119,576 B

$ arm-none-eabi-nm -S target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    | grep -E 'RSA_HEAP|ARENA|VFS_STORAGE|EFS_STORAGE|SECURE_PARTITION'
2003ddc4 00008004 b ...embassy_executor7_export5ARENA...   # 32,772
20045f5c 0000c000 b ...platform8rsa_heap8RSA_HEAP...       # 49,152
20051f5c 00008000 b ...device11EFS_STORAGE...
20059f5c 00008000 b ...device11VFS_STORAGE...
103f0000 00008000 b ...boot16SECURE_PARTITION...           # flash!
2001d560 000000f0 b ...boot7OTP_APP...                     # 240 — Phase D+E
200004cc 00000004 b ...boot10AUTH_STORE...                 # 4 — Phase D+E
# all RAM statics byte-identical to 35f39ab: the +36 B is .text/.rodata only

$ python3 tests/scripts/check_boot_chain.py
PASS: check_boot_chain (US-957) — worst call chain 66392 B <= 98304 B
  (main stack zone 119576 B, 98304 B chain ceiling)
  - per-root chains: 66392 B, 3140 B, 16 B, 8 B
  - 1164 register-indirect `blx rN` call sites in the ELF: not resolved into edges. …
  - task arena: demand 17744 B fits ARENA 32772 B (1.85x, floor 1.25x)

$ python3 tests/scripts/check_async_frame.py
PASS: check_async_frame (US-951) — async-task frame 9216 B <= 24576 B
  (main stack zone 119484 B, 24 KiB absolute ceiling 24576 B)
  - per-task-poll frames: 9216 B, 28 B, 8 B, 8 B

$ python3 tests/scripts/check_size_report.py
PASS: check_size_report (US-392) — text=951468 bss=412796 uf2=3592 blocks

$ python3 firmware/uf2gen.py target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    /tmp/rebaselined.uf2
picobin PT: 180 bytes embedded at 0x100dff00 (C data partition 0x102000..0x400000, US-413 S-413-2)
reset vector: 0x10000201 -> 0x10000201 (Reset, canonical entry — bootrom honors VT[1] per S-391-4)
/tmp/rebaselined.uf2: 3592 blocks (1 absolute preamble + 3591 ARM_S payload), 1839104 bytes
$ sha256sum /tmp/rebaselined.uf2 firmware/fapico2.uf2
6a13c4ac8cf7cf622061b725389f51595cce121140c040fce81ab06e3bacfcfe  /tmp/rebaselined.uf2
6a13c4ac8cf7cf622061b725389f51595cce121140c040fce81ab06e3bacfcfe  firmware/fapico2.uf2
$ cmp /tmp/rebaselined.uf2 firmware/fapico2.uf2 && echo "byte-identical"
byte-identical
```

**2026-09-27 re-baseline at `35f39ab` (Phases D+E) — historical, kept as
history.**

```bash
$ cargo build --release --target thumbv8m.main-none-eabi
$ arm-none-eabi-size target/thumbv8m.main-none-eabi/release/fapico2-firmware
   text	   data	    bss	    dec	    hex	filename
 949196	      0	 412704	1361900	  14c7ec	target/thumbv8m.main-none-eabi/release/fapico2-firmware

$ arm-none-eabi-size -A target/thumbv8m.main-none-eabi/release/fapico2-firmware
section                size        addr
.secure_partition     32768   272564224     # 0x103f0000 — FLASH, not RAM
.vector_table           276   268435456
.start_block             20   268435732
.text                897032   268435968
.rodata                18904   269333000
.data                  196   536870912     # RAM — Berkeley folds it into `text`
.gnu.sgstubs              0   269352128     # non-alloc, not in Berkeley `text`
.bss                 411680   536871112
.uninit                1024   537282792
# plus non-alloc .defmt 27, .comment 228, .ARM.attributes 48
# RAM statics = 196 + 411680 + 1024 = 412,900

$ arm-none-eabi-nm target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    | grep -E '_stack_(start|end)$'
20064ce8 B _stack_end
20082000 A _stack_start        # main stack zone = 0x1D318 = 119,576 B

$ arm-none-eabi-nm -S target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    | grep -E 'RSA_HEAP|ARENA|VFS_STORAGE|EFS_STORAGE|SECURE_PARTITION'
2003ddc4 00008004 b ...embassy_executor7_export5ARENA...   # 32,772
20045f5c 0000c000 b ...platform8rsa_heap8RSA_HEAP...       # 49,152
20051f5c 00008000 b ...device11EFS_STORAGE...
20059f5c 00008000 b ...device11VFS_STORAGE...
103f0000 00008000 b ...boot16SECURE_PARTITION...           # flash!
2001d560 000000f0 b ...boot7OTP_APP...                     # 240 — Phase D+E
200004cc 00000004 b ...boot10AUTH_STORE...                 # 4 — Phase D+E

$ python3 tests/scripts/check_boot_chain.py
PASS: check_boot_chain (US-957) — worst call chain 66392 B <= 98304 B
  (main stack zone 119576 B, 98304 B chain ceiling)
  - per-root chains: 66392 B, 3140 B, 16 B, 8 B
  - task arena: demand 17744 B fits ARENA 32772 B (1.85x, floor 1.25x)

$ python3 tests/scripts/check_async_frame.py
PASS: check_async_frame (US-951) — async-task frame 9208 B <= 24576 B
  (main stack zone 119576 B, 24 KiB absolute ceiling 24576 B)
  - per-task-poll frames: 9208 B, 28 B, 8 B, 8 B

$ python3 tests/scripts/check_size_report.py
PASS: check_size_report (US-392) — text=949196 bss=412704 uf2=3583 blocks

$ python3 firmware/uf2gen.py target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    /tmp/rebaselined.uf2
picobin PT: 180 bytes embedded at 0x100dfd00 (C data partition 0x102000..0x400000, US-413 S-413-2)
reset vector: 0x10000201 -> 0x10000201 (Reset, canonical entry — bootrom honors VT[1] per S-391-4)
/tmp/rebaselined.uf2: 3583 blocks (1 absolute preamble + 3582 ARM_S payload), 1834496 bytes
$ sha256sum /tmp/rebaselined.uf2 firmware/fapico2.uf2
141b12ace2fc3b2a53bff9537ecd609edfd745f0e675a8477a9caf9cdd635811  /tmp/rebaselined.uf2
141b12ace2fc3b2a53bff9537ecd609edfd745f0e675a8477a9caf9cdd635811  firmware/fapico2.uf2
$ cmp /tmp/rebaselined.uf2 firmware/fapico2.uf2 && echo "byte-identical"
byte-identical
```

**2026-09-27 re-baseline at `653b462` (Phases A–C) — historical, kept as
history.**

```bash
$ cargo build --release --target thumbv8m.main-none-eabi
$ arm-none-eabi-size target/thumbv8m.main-none-eabi/release/fapico2-firmware
   text	   data	    bss	    dec	    hex	filename
 948188	      0	 412584	1360772	  14c384	target/thumbv8m.main-none-eabi/release/fapico2-firmware

$ arm-none-eabi-size -A target/thumbv8m.main-none-eabi/release/fapico2-firmware
section                size        addr
.secure_partition     32768   272564224     # 0x103f0000 — FLASH, not RAM
.vector_table           276   268435456
.start_block             20   268435732
.text                896008   268435968
.rodata                18920   269331976
.data                  196   536870912     # RAM — Berkeley folds it into `text`
.gnu.sgstubs              0   269351104     # non-alloc, not in Berkeley `text`
.bss                 411560   536871112
.uninit                1024   537282672
# plus non-alloc .defmt 27, .comment 228, .ARM.attributes 48
# RAM statics = 196 + 411560 + 1024 = 412,780

$ arm-none-eabi-nm target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    | grep -E '_stack_(start|end)$'
20064c70 B _stack_end
20082000 A _stack_start        # main stack zone = 0x1D390 = 119,696 B

$ arm-none-eabi-nm -S target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    | grep -E 'RSA_HEAP|ARENA|VFS_STORAGE|EFS_STORAGE|SECURE_PARTITION'
2003dd4c 00008004 b ...embassy_executor7_export5ARENA...   # 32,772
20045ee4 0000c000 b ...platform8rsa_heap8RSA_HEAP...       # 49,152
20051ee4 00008000 b ...device11EFS_STORAGE...
20059ee4 00008000 b ...device11VFS_STORAGE...
103f0000 00008000 b ...boot16SECURE_PARTITION...           # flash!

$ python3 tests/scripts/check_boot_chain.py
PASS: check_boot_chain (US-957) — worst call chain 66392 B <= 98304 B
  (main stack zone 119696 B, 98304 B chain ceiling)
  - per-root chains: 66392 B, 3140 B, 16 B, 8 B
  - task arena: demand 17744 B fits ARENA 32772 B (1.85x, floor 1.25x)

$ python3 tests/scripts/check_async_frame.py
PASS: check_async_frame (US-951) — async-task frame 9208 B <= 24576 B
  (main stack zone 119696 B, 24 KiB absolute ceiling 24576 B)
  - per-task-poll frames: 9208 B, 28 B, 8 B, 8 B

$ python3 tests/scripts/check_size_report.py
PASS: check_size_report (US-392) — text=948188 bss=412584 uf2=3579 blocks

$ python3 firmware/uf2gen.py target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    /tmp/rebaselined.uf2
picobin PT: 180 bytes embedded at 0x100df900 (C data partition 0x102000..0x400000, US-413 S-413-2)
reset vector: 0x10000201 -> 0x10000201 (Reset, canonical entry — bootrom honors VT[1] per S-391-4)
/tmp/rebaselined.uf2: 3579 blocks (1 absolute preamble + 3578 ARM_S payload), 1832448 bytes
$ sha256sum /tmp/rebaselined.uf2 firmware/fapico2.uf2
cb698d323d0bb5ec2d7939dbaa73d726971af692caf5aedbc47b651745b0c421  /tmp/rebaselined.uf2
cb698d323d0bb5ec2d7939dbaa73d726971af692caf5aedbc47b651745b0c421  firmware/fapico2.uf2
$ cmp /tmp/rebaselined.uf2 firmware/fapico2.uf2 && echo "byte-identical"
byte-identical
```

**US-956 reproduction (2026-09-26) — historical, kept as history.**

```bash
$ cargo build --release --target thumbv8m.main-none-eabi
$ arm-none-eabi-size target/thumbv8m.main-none-eabi/release/fapico2-firmware
   text	   data	    bss	    dec	    hex	filename
 941520	      0	 412536	1354056	  14a948	fapico2-firmware

$ arm-none-eabi-size -A target/thumbv8m.main-none-eabi/release/fapico2-firmware
section                size        addr
.secure_partition     32768   272564224     # 0x103f0000 — FLASH, not RAM
.vector_table           276   268435456
.start_block             20   268435732
.text               890200   268435968
.rodata               18060   269326168
.data                  196   536870912     # RAM — Berkeley folds it into `text`
.bss                411512   536871112
.uninit                1024   537282624
# RAM statics = 196 + 411512 + 1024 = 412,732

$ arm-none-eabi-nm target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    | grep -E '_stack_(start|end)$'
20064c40 B _stack_end
20082000 A _stack_start        # main stack zone = 0x1D3C0 = 119,744 B

$ arm-none-eabi-nm -S target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    | grep -E 'RSA_HEAP|ARENA|VFS_STORAGE|EFS_STORAGE|SECURE_PARTITION'
2003dd28 00008004 b ...embassy_executor7_export5ARENA...   # 32,772
20045ec4 0000c000 b ...platform8rsa_heap8RSA_HEAP...       # 49,152
20051fc4 00008000 b ...device11EFS_STORAGE...
20059fc4 00008000 b ...device11VFS_STORAGE...
103f0000 00008000 b ...boot16SECURE_PARTITION...           # flash!

$ python3 tests/scripts/check_boot_chain.py
PASS: check_boot_chain (US-956) — worst task call chain 67288 B <= 98304 B
  (main stack zone 119744 B, 98304 B chain ceiling)
  - per-root chains: 67288 B, 51148 B, 1336 B, 300 B, 212 B, 208 B
  - task arena: demand 17744 B fits ARENA 32772 B (1.85x, floor 1.25x)

$ python3 tests/scripts/check_async_frame.py
PASS: check_async_frame (US-951) — async-task frame 9840 B <= 24576 B
  (main stack zone 119744 B, 24 KiB absolute ceiling 24576 B)
  - per-task-poll frames: 9840 B, 9216 B, 144 B, 144 B, 44 B, 40 B

$ python3 tests/scripts/check_size_report.py
PASS: check_size_report (US-392) — text=941520 bss=412536 uf2=3553 blocks

$ python3 firmware/uf2gen.py target/thumbv8m.main-none-eabi/release/fapico2-firmware \
    /tmp/us956.uf2
picobin PT: 180 bytes embedded at 0x100ddf00 (C data partition 0x102000..0x400000, US-413 S-413-2)
reset vector: 0x10000201 -> 0x10000201 (Reset, canonical entry — bootrom honors VT[1] per S-391-4)
/tmp/us956.uf2: 3553 blocks (1 absolute preamble + 3552 ARM_S payload), 1819136 bytes
$ sha256sum /tmp/us956.uf2 firmware/fapico2.uf2
fbaca7acce8fdb5b8e5c8ebc56a93740f19b0f5d0a6b96cf88bfcf462214b83f  /tmp/us956.uf2
fbaca7acce8fdb5b8e5c8ebc56a93740f19b0f5d0a6b96cf88bfcf462214b83f  firmware/fapico2.uf2
$ cmp /tmp/us956.uf2 firmware/fapico2.uf2 && echo "byte-identical"
byte-identical
```

The task-arena demand and the RSA peaks, which are not derivable from the ELF:

```bash
$ RUSTFLAGS="-Zprint-type-sizes" CARGO_TARGET_DIR=/tmp/us956-nightly \
    cargo +nightly build --release --target thumbv8m.main-none-eabi \
    | grep 'embassy_executor::raw::TaskPool<{async fn body of'
# ccid_task 8600 · hid_task 8136 · usb_task 736 · __embassy_main 160
# · led_heartbeat_task 56 · button_poll_task 56            = 17,744 B demand

$ cargo test -p fapico2-openpgp --test rsa_heap_peak \
    --target x86_64-unknown-linux-gnu --offline -- --nocapture --test-threads=1
US956 INFO device_heap=49152 B = 48 KiB; mirror and platform/src/rsa_heap.rs agree
US942 SUMMARY bits=2048 unlimited_peak_max=7018  device_heap=49152 verdict_fits=FITS
US942 SUMMARY bits=3072 unlimited_peak_max=13034 device_heap=49152 verdict_fits=FITS
US942 SUMMARY bits=4096 unlimited_peak_max=13162 device_heap=49152 verdict_fits=FITS
US956 MARGIN worst_peak=24792 B device_heap=49152 B headroom=24360 B multiplier=1.98x
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Host-side gates (the `--target` flag is mandatory — `.cargo/config.toml`
defaults `build.target` to `thumbv8m.main-none-eabi`):

```bash
cargo test    --workspace --exclude fapico2-firmware --target x86_64-unknown-linux-gnu
cargo clippy  --workspace --exclude fapico2-firmware --target x86_64-unknown-linux-gnu \
              --all-targets -- -D warnings
python3 tests/scripts/check_size_report.py   # doc↔ELF consistency gate
python3 tests/scripts/check_async_frame.py   # frame <= min(24 KiB, real stack zone)
python3 tests/scripts/check_boot_chain.py    # call chain + task arena (US-956)
```

**The `firmware/fapico2.uf2` artifact changed again in the factory-wipe
re-baseline** — sha `141b12ac…` → `7ed20272…`, with the **block count and byte
length unchanged** at 3,583 blocks / 1,834,496 B, because the +36 B of `text`
does not cross a 512 B boundary. This is the only re-baseline in the epic's
history where the artifact's *length* did not move; the content did, and the
sha records it.

**The `firmware/fapico2.uf2` artifact changed again in the Phase D+E
re-baseline** — 3,579 → 3,583 blocks, sha `cb698d32…` → `141b12ac…`, a
2,048 B step over the OTP/OATH commits. (The same day's Phases A–C
re-baseline was the larger 3,553 → 3,579, sha `fbaca7ac…` → `cb698d32…`,
13,312 B step; the committed UF2 had been stale at `653b462` and
regenerating it was part of that re-baseline.) The regeneration is
deterministic from the release ELF (`cmp` pass above), so the UF2-staleness
concern that US-950 and US-951 each had to fix does not recur.
Earlier steps: US-956 3,555 → 3,553; US-951 3,811 → 3,555.

- `firmware/fapico2.uf2` — **2904 blocks**, 1,486,848 bytes — the image at
  the US-966 tip (rebuilt release ELF → `firmware/uf2gen.py`; the artifact is
  regenerated, **not** flashed — see the device-state note below).
- sha256: `b639432c0a2ea0662e7468aa8fc08476e49994aee1b8b349034a0355bc36ad51`
  (supersedes US-964's `50e89b94b9a6…`, 3553 blocks, which in turn superseded
  US-956's `fbaca7ac…`, 3553 blocks, US-959's `27af263b…`, 3552 blocks,
  US-951's `6b8f8761…`, 3555 blocks, the US-951 report-sweep artifact
  `12485f16…`, 3811 blocks, and US-950's `afd5c170…`, 3816 blocks)
- **This artifact has NOT been flashed.** US-966 is host-only by scope. The
  card on the bench is still running the pre-US-966 image, and its signing
  slot `C1` still holds the now-unserved P-384r1 attribute, so the next flash
  needs a card factory reset or `C1` restored to a supported algorithm
  **first**. `docs/tasks/us966-defer-bp384.md`; `known-gate-divergences.md` →
  the US-954 carry-forward, dated US-966.
- US-956 verified determinism: the regeneration into `/tmp` is
  byte-identical to the artifact it commits (`cmp` pass), continuing the
  US-950 → US-951 record.
- **This artifact is still not hardware-validated.** US-956 is what makes it
  *bootable in principle* — 412,732 B of statics and an 88,348 B worst-case
  call chain against a 532,480 B part leaves 31,396 B of margin — but every

## Current artifact (US-1007 defect fix, re-measured 2026-09-29; the I-1 / US-1011/US-1012 / US-1010 / US-161/162/163 / US-160 / factory-wipe / Phases D+E / US-956/US-951/US-939/US-715 listings below are historical)

- `firmware/fapico2.uf2` — **3037 blocks**, 1,554,944 bytes — the image at
  the US-1007 defect-fix tip, regenerated by `./build.sh` (rebuilt ELF →
  `firmware/uf2gen.py`) from the **stable** toolchain. **Two blocks larger
  than the I-1 image it supersedes**: making keygen fallible and capping the
  curve crates' rejection sampler moved `text` by **+496 B**, which crossed
  two 512-byte UF2 block boundaries. The image it supersedes was one block
  larger than US-1011/US-1012 because the bounded `probe_bytes` sanity draw
  moved `text` by **+104 B**; the counter batching before that moved `text`
  by −44 B and stayed inside one block, so that image kept the US-1010
  count.
- sha256: `a5a7459757d716dd637dc43d7fc97e73e98d28474e6d901bcaad569184300b48`
  (US-1020 presence instrumentation, 3,038 blocks; supersedes the
  2026-09-29 clock fix, 3,037 blocks, sha256
  `77edc4ea935a5ab81099fb561676fe77e863f87da42d26290b0b95c3428b7845`,
  which superseded the US-1007 defect fix
  `eb48c0bbc7f7…`, 3,037 blocks, which superseded the I-1
  `834bc4505f23…`, 3,035 blocks, which superseded the US-1011/US-1012
  `805e872d42ec…`, 3,034 blocks, which
  superseded the US-1010 `e70dc34be002…`, 3,034 blocks, which superseded the
  device-identity `071b245e46b9…`, 3,027 blocks, which in turn superseded the
  `feat/picompat` → `fix/openpgp` merge image of the same block count, and
  behind that the US-161/162/163 `6a13c4ac8cf7…`, 3592 blocks — the listing
  that follows is that older lineage, kept as history)
- **Determinism re-verified at this re-measure too:** regenerating into
  `/tmp` with `firmware/uf2gen.py` is `cmp`-identical to the committed
  artifact, so the sha256 above is reproducible from the release build and
  not a one-off.
- Embedded PICOBIN partition-table block (C data partition
  `0x102000..0x400000`, US-413 S-413-2) at `0x100bd800` in this image; the
  reset vector is the canonical `0x10000201`. Both are reported by
  `firmware/uf2gen.py` on every run (this run: `0x100bd900`).
- **This artifact is still not hardware-validated for this story.** The
  counter-batching stories' hardware legs — in particular the RP2350 run of
  the FIDO suite and the power-cut ceremony that US-1012's monotonicity claim
  ultimately rests on — are named as outstanding in
  `docs/tasks/rskey-adopt-context.md`; what is measured here is linker
  arithmetic and a host-side build. **This fix adds to that list:** the
  interleaving of `Rp2350Probe` and `embassy-rp`'s driver over one TRNG
  singleton (D-11) is argued from source symmetry and has never run on
  silicon. 420,532 B of statics and a 92,712 B
  worst-case call chain against a 532,480 B part leave 19,232 B of stack-zone
  margin (17.2 %), and 5,592 B of headroom against the chain ceiling — see
  "The headroom that is thinner than it looks" above, which is the number to
  read before adding to this path.
