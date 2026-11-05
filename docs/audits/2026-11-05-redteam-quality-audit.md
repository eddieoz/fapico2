# Red-team suite quality audit — tautologies, ghosts, fabrication

**Date:** 2026-11-05 · **Scope:** every script in `redteam/` (20 files) plus the
round-3 findings they cite. **Standard:** a red-team artifact must *prove* an
exploit — it must be able to fail, it must exercise the code path it names, and
every claim it makes about the target must be true of the current tree.

Verdicts per script are below; the classes are:

- **Fabrication** — the script's central claim does not match the target, or
  the "exploit" could not have succeeded even against a vulnerable target.
- **Tautology** — the script cannot fail, or its pass condition is satisfied
  for a trivial reason (uniform refusal before the code under test ever runs).
- **Ghost** — stale state assumptions, dead code, citations to things that are
  not in the tree, or tests described in a docstring but never implemented.

---

## Fabrication-class findings

### A1 · `oath_exploit.py` — the "full compromise" exploit's MAC is computed over the wrong challenge

The script's docstring promises SELECT → salt → derive → VALIDATE → LIST →
CALC → PUT, and calls itself the OATH full-compromise exploit. Both crypto
directions are inverted relative to the target and to the YKOATH spec:

```python
# oath_exploit.py:32-34 (as committed)
host_mac = hmac.new(key, host_challenge, hashlib.sha1).digest()
body = bytes([0x74, 8]) + host_challenge + bytes([0x75, 0x14]) + host_mac
```

The firmware (`apps/oath/src/oath_core.rs:2715` `cmd_validate`) verifies the
host's `75` response against `HMAC(key, self.challenge)` — the **device
challenge from SELECT** — and answers with `HMAC(key, chal)` over the **host
challenge from the VALIDATE body**. The script sends `HMAC(key,
host_challenge)` as its proof (guaranteed `6A80` SW_DATA_INVALID on a board
where the default code *is* active) and then "verifies" the device MAC against
`HMAC(key, device_challenge)` (`:58`), also backwards.

The correct dialect is already in the tree and proves the point:
`tests/harness/test_redteam.py:194` (`_validate_tlv`) MACs the **SELECT**
challenge. Both first-party clients (`yubikit/oath.py::_derive_key` users) do
the same.

**Consequence:** F4 (`SECURITY-ASSESSMENT-ROUND3.md`, HIGH-latent) has never
had a working exploit. The hardware VALIDATE in round 3 was refused `6984`
because the board had a real code — the script would have answered `6A80` even
on a default-code board. Fixed in this commit (proof runs in CI against the
emulator, where the default code *is* the state: see
`tests/harness/test_redteam_round3.py::test_f4_default_access_code_takeover`).

Secondary defects in the same file: the PUT leg the docstring advertises does
not exist; the "device MAC matches" check would have inverted-verified a
hostile device.

### A2 · `ccid_raw.py` — a CCID driver whose frames cannot parse on any CCID device

The bulk CCID message header is 10 bytes (`bmMessageType` 1, `bMessageSpecific`
3, `dwLength` 4 LE, payload). This driver:

- builds the outbound header as 8 bytes with the APDU length as a **single
  byte at offset 7** (`:69`) — the length lands inside `dwLength`'s third byte
  position and the payload offset is wrong by two;
- prepends `[seq, 0, 0, 0]` (`:40`), so the device reads the sequence number
  as `bmMessageType`;
- parses the inbound header as if `bMsgType` were at offset 5 and
  `wDataLength` at 7..9 (`:44-50`) — both wrong (type is 0, `dwLength` is
  6..10 LE).

Nothing imports it, and the round-3 report's CCID evidence came from
`ccid.py` (PC/SC). So this is a fabricated driver that was never exercised —
its docstring ("no pcscd, no sharing violations") describes a capability it
does not have. Deleted in this commit; the honest fix is either the pico-fido2
relay framing (which `tests/harness/ccid.py` already speaks) or a corrected
libusb implementation.

---

## Tautology-class findings

### T1 · `timing.py` — a timing test constructed so it can never detect the leak it names

The docstring states the threat (per-digit early exit in PIN verify) and then
the analysis section pre-writes the exculpatory conclusion: *"a per-digit
early exit would show as spread <~50 ms on the *verify* stage, masked here by
ECDH."* With 3 samples, a ~1192 ms ECDH handshake dominating, and USB jitter
of milliseconds, **no** implementation of the leak the script names could move
the numbers it prints. The script is unfalsifiable — it always "finds" no
leak.

A testable version must isolate the verify stage (differential: same-length
wrong PINs × N≥30 on a token that mints no ECDH, or compare PIN-verify latency
against a no-PIN command's), or probe an observable the ECDH does not dominate.
Until then the script should print "inconclusive by construction", not a
clean-bill analysis. Also carries the ghost state assumption "we have 7
retries left after the earlier single wrong PIN" (an operator-session fact,
not a property of the target).

### T2 · `pgp_malleability.py` — uniform refusal is reported as "no invalid-curve oracle"

Three defects:

1. **The canary is missing.** The verdict logic (`:103-112`) calls UNIFORM
   "no malleability" — but every mutation in class A returns the same SW iff
   the applet refuses *before* its ECDH (no PW1 session, malformed DDO, …).
   The round-3 report recorded all 12 mutations → identical `6A86`, including
   the "base" input. When even the *well-formed* input is refused, uniformity
   is a property of the gate, not of the curve check, and proves nothing. A
   valid sweep needs a control: an *authenticated, valid* PSO:DECIPHER must
   succeed first, then the mutations get a uniformity meaning. As written the
   test cannot fail on a fully-gated applet — the definition of a tautology.
2. **Dead mutation:** `neg-y` (`:66`) — `(BASE[31] ^ 0x80) if False else
   BASE[31]` is a no-op that re-sends `BASE`. One of twelve "mutations"
   mutates nothing, and its result is counted in the verdict.
3. **Ghost code:** `decipher_body` (`:28-34`) is defined, never called; the
   docstring describes DDO-wrapped `7F47` structures but the probes send raw
   `[0xB6, len] + point` APDUs, a different (and valid) input shape than the
   one the prose describes.

### T3 · `fido_malleability.py` §3 — a test named in the docstring and never implemented

The module docstring promises four questions; question 3 — *"does a mutated
response frame get accepted on the next command (i.e. does the device validate
anything about the channel it just used)?"* — has no code: no response frame
is mutated anywhere in the file, and the `r` captured in `cmd()` is discarded.
Sections 1, 2 and 4 are real. A reader auditing the file from its docstring
believes a channel-validation probe exists. Either implement it (mutate the
returned CBOR, resend with the same CID, compare) or delete the claim.

---

## Ghost-class findings

### G1 · `pin_recover.py` — a scenario record posing as a reusable probe

The docstring narrated one specific board's history ("Before the freeze …
unauthenticated Rescue REBOOT → enumeration failure (board frozen) … user
power-cycled"). Its live question — "do retries persist across a power
cycle" — is a legitimate leg `reboot_retry.py` does not cover (reboot ≠
unplug), so the script is kept but rewritten as a reusable probe: it reads
the counter, instructs the operator to power-cycle, re-reads, and exits with
the verdict (0 persisted / 1 reset / 2 env). The scenario narrative belongs
to the assessment record, not the tool.

### G2 · Operator-session state hardcoded as if it were target state

`timing.py:19-21` ("we have 7 retries left after the earlier single wrong PIN.
Budget 3") and `pin_attack.py` ("2 of N retries burned") encoded the previous
manual session's burn-down. On a fresh board these budgets are wrong;
`timing.py` would spend 5 retries unconditionally without reading a baseline
first. Both now compute the budget from the device's own `getPinRetries` at
run time and refuse to burn attempts below a stated floor.

### G3 · Environment ghosts — `hidraw8` hardcoded inconsistently

`ctaphid.py` honours `FA_HIDRAW`, but `hid_fuzz.py:10`, `hid_framing.py:9`,
`hid_reassembly.py:8` and `fido_malleability.py` hardcoded `"/dev/hidraw8"`
directly, so the env var only sometimes worked. All four now derive the path
from `ctaphid.DEV` (the `FA_HIDRAW` default), so one variable moves the whole
suite to another hidraw node.

### G4 · Ghost citation in the harness

`tests/harness/test_redteam.py:9` cites the red evidence as
`redteam/out/ASSESSMENT_REPORT.md` — a path that does not exist and never did
in this repository (the round-1 report is not in the repo; the round-2/3
records live in `docs/archive/`). The finding IDs R1–R12 are traceable only
through that dangling reference. Corrected here to point at
`docs/archive/SECURITY-ASSESSMENT-ROUND2.md`.

---

## Claims verified TRUE (fabrication check passed)

Every load-bearing source citation in the suite was checked against the tree:

| Claim | Where | Verdict |
|---|---|---|
| `DEFAULT_ACCESS_CODE = b"123456"`, auto-provisioned at boot | `apps/oath/src/oath_core.rs:396`, `:1089` | ✓ real |
| PBKDF2-HMAC-SHA1(password, device_id, 1000, 16) | `oath_core.rs:403`, `:721` | ✓ real |
| Salt (device_id) published in SELECT TLV `0x71`, unconditionally | `oath_core.rs::select_apdu` (TAG_NAME always; `0x74` challenge only when a code is set) | ✓ real — and this divergence from YubiKey (which withholds the name when a code is set) is what makes F4 remotely exploitable at all |
| OATH VALIDATE challenge/response direction | `cmd_validate` `oath_core.rs:2715` | ✓ source right, **exploit wrong** (A1) |
| OATH LIST/CALC/PUT/DELETE/RENAME presence gates: SET_CODE/CALC/RESET only | `grep user_present` in `oath_core.rs` | ✓ real (F4) |
| `cmd_validate` has no retry counter | `oath_core.rs:2715-2742` | ✓ real (F4) |
| vendor41 decision table (MSE ungated, EXPORT/LOAD touch, …) | `apps/fido/src/vendor41.rs:770` `decision()` | ✓ real |
| otp_hid framing (8/7/70/10) | `platform/src/otp_hid.rs:103-117` | ✓ real |
| mgmt `INS_MIGRATION` has no presence grant; host builds answer INS_NOT_SUPPORTED | `apps/mgmt/src/lib.rs:167`, `:459`, `:950` | ✓ real (F6) — note this also means **F6 is hardware-only by construction**; no emulator proof is possible until the migration handler is wired on host builds |
| opcard `// TODO: check CLA` | `vendor/opcard/src/command.rs:244` | ✓ real (F10) |
| F1/F3 fixed (reset gate, IV honesty) | `SECURITY-ASSESSMENT-ROUND3-REMEDIATION.md` + `apps/fido/tests/reset_presence_gate.rs` | ✓ verified |

---

## Efficiency findings

- **Three private copies of the same raw-HID plumbing** (`hid_fuzz.py`,
  `hid_framing.py`, `hid_reassembly.py` each define `drain/w/frame`-shaped
  helpers). Not consolidated in this pass — only the device-path convention
  was unified (G3). Consolidating on `ctaphid.py` is the recorded follow-up:
  the copies drift (hid_framing's seq-bit handling already differs from
  hid_fuzz's), and a drift in an attack tool is a false negative generator.
- **No exit codes anywhere.** Every script prints and exits 0, so no gate —
  CI, a release checklist, or a nightly — can treat "exploit worked" as a
  signal. All scripts now end with a `verdict()` call: exit 0 = attack
  refused (device held), exit 1 = **exploit succeeded / defect observed**,
  exit 2 = environment error (not a security result).
- **`oath_exploit.py` vs `test_redteam.py` duplication:** the correct
  handshake now exists once in the harness; the hardware script imports the
  same derivation helpers instead of re-deriving them wrongly.

## What "prove, not point" changed concretely

1. The one exploit in the suite was broken; it is fixed and now **runs and
   proves F4 end-to-end in CI** (`tests/harness/test_redteam_round3.py`) on
   the emulator, where the default access code is the boot state — the exact
   condition round 3 could not arrange on the board.
2. F8 (pinUvAuth protocol 1 advertised and answered) is proven on the emulator
   over CTAPHID in the same suite.
3. F5/F6/F10 remain hardware-leg-only; the audit records why (emulator
   auto-ack presence, host-build migration handler absent, opcard CLA path)
   and what each proof requires.
