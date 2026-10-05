# Debug access is the objective; every other gate is a delay

**Finding:** red-team F2 (HIGH, *accepted*). **Applies to:** every image until
the first `-release` tag. **Verified by:** US-1613,
`scripts/check_release_debug_state.sh`.

This note exists because "accepted risk" is the phrase most likely to be
misread as "handled", and this one is not handled — it is *scheduled*. It
states the window, what it exposes, what it makes irrelevant, and the exact
condition under which it closes.

---

## The window

While `CRIT1.DEBUG_DISABLE` and `CRIT1.SECURE_DEBUG_DISABLE` are unset, the
RP2350 accepts an SWD debugger. Measured on the live board
(`redteam/SECURITY_ASSESSMENT.md` F2, 2026-10-05, `picotool info -a` over
BOOTSEL):

```
secure boot:            0
debug enable:           1
secure debug enable:    1
```

**The closure is the first `-release` tag**, per
[`adr/0002-provisioning-policy.md`](adr/0002-provisioning-policy.md). The
repository carries no tags, so every image built so far is pre-release and
this reading is *consistent with policy* — it is not evidence of a defect.
What it does mean is that the window is **open today**, and "consistent with"
is not the same as verified, which is what US-1613 exists to change.

There is no build flag that closes it. These are OTP fuses sampled by the
bootrom at reset (`pico-sdk/.../regs/otp_data.h:346-352`); CI cannot burn
them, and burning them is irreversible — a board that later needs SWD cannot
be unlocked. `docs/secureboot.md` carries the provisioning procedure, and
ADR 0002 §"What is deferred" records that the device-side provisioner
(`platform/src/boot_key.rs`) is **dead code whose row map does not match the
bootrom**, which is the hard prerequisite for any burn and is not yet
satisfied.

## What it exposes

Brief physical possession, and an attacker who can read RAM gets everything
the firmware holds there:

| what | why it matters |
|---|---|
| `derive_store_key(otp_key_1, chipid)` output | the key the sealed store is written under — the whole FIDO **and** OATH key set |
| the ECDH `hkey` | the persistent PIN-agreement key; recovering it collapses the clientPIN handshake |
| `device_random` | binds the key region and the getInfo encrypted-state fields |
| per-applet keys | OpenPGP keys, OTP slot secrets, the vault |

**This is complete key exfiltration.** It is also the channel the round-2
assessment already proved works end to end: a 4 MiB flash image came out over
BOOTSEL including the sealed store at offset `0x20B001`, and OTP row `0xE90`
resists read attempts (`picotool otp get 0xE90` → *permission failure*). The
flash boundary holds. **The debugger is the way around it** — RAM is not
protected from a debugger by anything on this part.

## What it makes irrelevant

This is the sentence that matters, and it is the reason the note is filed
under the F1/F3 epic rather than left in a report:

> While debug access is open, **every other control in this system is a delay,
> not a barrier.** They raise the cost of a purely *logical* attacker — one
> with USB access and no physical possession of the chip. They do nothing
> against an attacker who can attach a probe, because that attacker reads the
> secrets directly and never has to defeat a gate.

Concretely, each of the following is a wall with no roof:

- **F1's presence gate on `authenticatorReset`** (US-1601…US-1606). Prevents
  the one-frame wipe over USB. An attacker with a debugger reads the keys the
  wipe would have destroyed.
- **F3's removal of the getInfo counter oracle** (US-1608…US-1609). Stops an
  unauthenticated poller learning when an assertion occurred. An attacker with
  a debugger reads the counter directly.
- **`alwaysUv` / `makeCredUvNotRqd` / `clientPin`** (AGENTS.md §4). A client
  reads these and builds its behaviour on them, and this firmware now honours
  all three. Honouring them is worth doing and is not a defence against
  physical access.
- **The key region's sealed records, and the OTP row the store key mixes in.**

This is not an argument that those gates are not worth landing — they are,
and F1 in particular was a one-frame total loss over plain USB. It is an
argument against reading them as *the* security property. **The security
property is the debug closure.** Until it fires, this device's threat model is
"an attacker with brief physical possession wins", and every gate in the
repository is defence in depth beneath that statement.

## Operational rule while the window is open

**Never attach an SWD debugger to this firmware during ordinary validation.**
`probe-rs run` and `gdb … load; monitor reset` make `OTP_DATA_RAW` reads return
`0xFFFFFFFF`, which embassy-rp maps to `InvalidPermissions`, which
`read_otp_key_1()` reads as "no key" — so `fatal_boot` fires *before* USB is
constructed. The result is a false "the OTP key row is unreadable" failure on a
perfectly healthy board, **including on known-good commits**. Validate
detached, over BOOTSEL. Use the probe to **read**, never to run.

This is also why the round-2 assessment did not attach a debugger to gather
F2: it would have bricked OTP reads for the rest of that session *and*
violated the rule. The reading above is `picotool info -a` over BOOTSEL, which
touches no OTP row.

## How the closure gets verified

[`scripts/check_release_debug_state.sh`](../scripts/check_release_debug_state.sh).
It is deliberately **not** in `run_tests.sh` — it needs hardware — and is
wired into the release checklist instead.

```bash
# Before tagging a release. Requires the board in BOOTSEL and picotool.
./scripts/check_release_debug_state.sh --class release     # exit 0 required

# Offline, against a saved capture.
./scripts/check_release_debug_state.sh --from-text cap.txt --class release

# Parser + policy, no hardware. This is what CI can run.
./scripts/check_release_debug_state.sh --self-test
```

A release must read `secure boot: 1`, `debug enable: 0`,
`secure debug enable: 0`. The script gates **both directions**: it also fails
a *pre-release* image that reads as closed, because a closure that fired
early would have burnt a fuse nobody intended and that board can never be
used for ordinary development again. A gate that can only catch one of those
is half a gate.

It distinguishes "the posture is wrong" (exit 1) from "the posture could not
be observed" (exit 2), because a `picotool` invocation that printed nothing
must never be reported as a closed debug port.

### What is verified and what is not

- **Verified:** the parser and the policy, against the one hardware reading
  this repository holds (`redteam/SECURITY_ASSESSMENT.md` F2) in both
  directions. `--self-test` exits 0.
- **Not verified:** that the closure *fires* on real hardware. No fuse has
  been burned; ADR 0002 defers it to the first `-release` tag, and the
  post-closure reading in the self-test is **synthesised, not measured** — the
  script says so in its own source. Before the first tag, run the script
  against the real device and record the output here.

That last line is the standing obligation this note carries, and US-1613's
acceptance criterion. Until it is discharged, this file is a description of an
open window, not a description of a closed one.

## Related

- [`adr/0002-provisioning-policy.md`](adr/0002-provisioning-policy.md) — the
  decision that the closure is deferred, and why nothing is burned yet.
- [`secureboot.md`](secureboot.md) — the signed-boot provisioning procedure
  and the `CRIT1` flags it touches.
- [`SECURITY-ASSESSMENT-ROUND2.md`](SECURITY-ASSESSMENT-ROUND2.md) §16, §18 —
  the flash-extraction chain and the limits of same-domain confidentiality.
- [`known-gate-divergences.md`](known-gate-divergences.md) — the other places
  this firmware records a deliberate divergence rather than inheriting one.
- AGENTS.md, *Hardware warnings* — the SWD rule above, in its original form.