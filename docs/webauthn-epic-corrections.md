# WebAuthn browser-discovery epic — corrections to the plan

**Read this before trusting `docs/tasks/EPIC-webauthn-browser-discovery.md`.**

The epic plan for `FIDO-WEB-BROWSER-DISCOVERY` (US-1501…US-1527) is a good
piece of work and most of it is right. It is also **not durable**: `docs/tasks/`
is gitignored (`.gitignore:79`, confirmed by `git check-ignore -v`), as is the
progress ledger `.superpowers/sdd/` (`.gitignore:60`). Neither the plan nor the
ledger is in version control. If both working files are lost, the *corrections*
below are lost too — the fixes live in code, but the record of *what the plan
said and why it was wrong* currently exists only in gitignored files and in
commit prose.

So this document is that record. It carries **only the corrections and the
audit discipline**. The measurements themselves are not restated here; they live
in the four tracked evidence documents and are linked at the end.

Nothing here is firmware. Every correction is a statement about the plan or
about a value; each names where the correction now lives in the tree.

---

## How to trust this document

**Every claim below was re-checked against the tree while this file was
written**, not carried over from the ledger. Where a correction could be
checked by *running* something, it was. Each entry is tagged:

| tag | meaning |
|---|---|
| **executed** | a command was run and its output is quoted or named here |
| **read** | settled by reading source, a header, or a reference tree |
| **executed + read** | the two agree, and the agreement is the point |

**The base for "what the plan said" is `2c29d29`** — the last commit before this
epic's first fix (`63e2bcf`, US-1507). The plan's `file:line` citations were
spot-checked against that tree and are largely accurate: §2.1 (`tasks.rs:538` the
read, `:621` the inline dispatch, `presence.rs:108` the 30 000 ms window), §2.2
(the catch-all `else` at `tasks.rs:983`), §2.3 (`reply_hid` at `tasks.rs:991-999`
with no deadline), §2.4 (`hid_control.rs:18` the report descriptor), §2.7
(`ctap2.rs:409`, `device_core.rs:2019`), §2.8 (`emul_main.rs:273`, the second
`HidAssembler` struct) and §2.9 (`device_core.rs:1860-1872`, the `uv`
justification) all land where the plan says. Several are now stale because the
fixes moved the lines, which is normal. One count drifted: §4 item 6 says
`emul_main.rs` carries **two more copies** of the blocking presence loop "(lines
962, 983, 1084)"; at base there are **two** `CTAP_TOUCH_WINDOW_MS` sites, `:985`
and `:1086`. Not load-bearing — US-1524 replaced the emulator's copy with the
shipped loop anyway.

**The discipline this document records.** On this branch a confident claim
inverted **twelve** times when it was executed rather than read — six of them
statements in the plan itself (§"The audit" below). The pattern is not random:
it is always a claim about *what a client does*, established by reading a
header or a spec and then transcribed into a comment. Every one of those six
involved a value or a behaviour that had to be observed on a wire, in a
browser, or through a decoder. **Treat any statement in this repository about
client behaviour that has no executed measurement behind it as unproven.**

---

## The corrections

### C1 — `CTAP2_ERR_KEEPALIVE_CANCEL` is `0x2D`, not `0x2C`

**The plan said** (US-1506): "on cancel and on expiry the answer is
`CTAP2_ERR_KEEPALIVE_CANCEL` (`0x2C`, declared at `ctap2.rs:69` and produced
nowhere today)".

**What is true:** the byte is **`0x2D`**. `0x2C` is `CTAP2_ERR_INVALID_OPTION`,
a different error entirely — the one the `up: false` rejection deliberately
returns.

**Evidence** (executed + read):

- Executed `fido2` 2.2.1's decoder, the library `AGENTS.md` §2 tells you to
  read rather than the spec:
  `fido2/ctap.py:145-146` → `INVALID_OPTION = 0x2C`, `KEEPALIVE_CANCEL = 0x2D`;
  confirmed at runtime —
  `CtapError.ERR.KEEPALIVE_CANCEL → 45` (`0x2D`), `INVALID_OPTION → 44` (`0x2C`).
- Read: `../pico-fido2/src/fido/ctap.h:176` `#define CTAP2_ERR_KEEPALIVE_CANCEL
  0x2D`; `../pico-fido2/pico-keys-sdk/src/usb/hid/hid.c:41`
  `#define CTAPHID_KEEPALIVE_CANCEL_STATUS 0x2D`, emitted at `hid.c:393`.
- The C reference's whole `0x2B…0x2D` window is contiguous and matches
  (`ctap.h:174-176`: `UNSUPPORTED_OPTION 0x2B`, `INVALID_OPTION 0x2C`,
  `KEEPALIVE_CANCEL 0x2D`), so a table shifted by one across that window cannot
  be right at three consecutive values by accident.

**Where the correction lives:** `firmware/src/ctap_hid.rs:106`
(`CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D`, with the derivation in its doc
comment) and `apps/fido/src/ctap2.rs:148` (`KeepAliveCancel = 0x2D`).
Introduced by `e47665d`; the `apps/fido` side aligned by `8048e30`.

**Open:** nothing for the byte itself. `fido2` maps `KEEPALIVE_CANCEL` to
`ClientError.TIMEOUT` and would have mapped `0x2C` to `BAD_REQUEST` — the
difference between "the user abandoned it" and "your request was malformed"
(`firmware/src/ctap_hid.rs:89-95`).

---

### C2 — A `CTAPHID_CANCEL` must **not** be acknowledged

**The plan said** (US-1505, and §7 Definition of Done item 3): "the window
closes, the keepalives stop, and the device answers a **zero-length
`CTAPHID_KEEPALIVE`** per §11.2.9 — never `ERROR`/`INVALID_CMD`".

**What is true:** no acknowledgement frame is sent. The only frame that leaves
is **the cancelled command's own answer**, on the cancelled command's channel.
Two independent reasons, both checked:

**Evidence** (executed + read):

- Executed the inbound matcher in `fido2/hid/__init__.py:218-236` against
  synthetic 64-byte frames:
  - a reply whose CMD byte is `0x11` matches none of `TYPE_INIT|cmd`,
    `TYPE_INIT|CTAPHID.KEEPALIVE`, `TYPE_INIT|CTAPHID.ERROR`, so the `else` at
    line 235-236 fires → **`CtapError(INVALID_COMMAND)`**;
  - a reply with CMD `0x3B` (KEEPALIVE) and a **zero-length** payload reads its
    status byte from the frame's zero padding, `STATUS(0x00)` is not a member of
    `fido2/ctap.py:37-41` (`PROCESSING = 1`, `UPNEEDED = 2`), so the `except
    ValueError` at line 227-228 fires → **`ConnectionFailure("Invalid keepalive
    status")`**.
  So the frame the plan specified would break the client that sent the cancel,
  and the same failure arrives *later*, corrupting the next command on that
  channel, if the `0x11` is sent after the `0x2D`.
- Read, both references: `../pico-fido2/pico-keys-sdk/src/usb/hid/hid.c:377-395`
  handles `CTAPHID_CANCEL` and `return 0;` — the one frame it does write there
  (`hid_write(64)` at `hid.c:394`) is the *cancelled CBOR command's* `0x2D`
  answer, not an ack. `../RS-Key/crates/rsk-usb/src/ctaphid.rs:703-708`: "A
  CANCEL is never acknowledged (CTAPHID spec). With no transaction in flight it
  is simply ignored"; `../RS-Key/CHANGELOG.md:13386-13388` records that RS-Key
  *had* an ack and removed it.
- Read, measured on the board before the fix: with no window open a `CANCEL` was
  answered `0x3F` / `0x01 INVALID_CMD` in ~12 ms
  (`docs/webauthn-discovery-baseline.md`, part (c1)).

**Where the correction lives:** `firmware/src/hid_serve.rs:914-1006` (the
`CTAP_HID_CANCEL` arm; the "No acknowledgement frame — deliberately" section is
at `:927-956`, and "A CANCEL with no window open" at `:957`). The no-window case
is silence for the same reason, which is why its test asserts *nothing was sent*
rather than asserting bytes.

**Open:** none.

---

### C3 — The `capFlags` fix is right; the plan's claim about it was overstated

**The plan said** (§3, on US-1507): "`capFlags` is advertised as `0x04` … **A
host that reads `0x04` under the spec sees 'WINK yes, CBOR no'** … **This is a
verified defect and a far better fit for the reported symptom than the
blackout**, because it is a *cold-start, discovery-time* defect … a strict host
reads the INIT reply, concludes there is no CTAP2 device, and never offers it."

**What is true:** `0x05` is the correct value and it is reference parity. But the
epic's *reasoning* does not survive measurement:

- The **CBOR bit `0x04` was already set on both boards**. The pre-fix Rust board
  sent `capFlags = 0x04`; the C reference sends `0x05`. Under the de-facto
  convention — the one every first-party tool uses, verified by *executing*
  `fido2.hid.CAPABILITY` → `{'WINK': 1, 'LOCK': 2, 'CBOR': 4, 'NMSG': 8}` — both
  boards already read as "CBOR supported". Measured on both boards:
  `docs/webauthn-discovery-ab.md`, "fido2 parsed this device as:
  … capabilities=0x04" (board A) and "… capabilities=0x05" (board B).
- The bit that actually differs is **`0x01`**, and `0x01` is **WINK under every
  convention verifiable on this machine**. The claim rested entirely on the spec
  column, which could not be verified here.
- **The A/B probe never observed a browser.** It proves which bytes differ
  between two boards. It does not prove which byte a browser acts on.

So `0x05` is honest — the device serves both CBOR and WINK — and harmless under
the convention that *is* verified. It is **not a demonstrated fix for
discovery**, and the plan's "if a browser turns out to honour capFlags, this one
byte is the whole bug" is not established.

**Evidence** (executed + read): the two-board measurement above; read
`../pico-fido2/pico-keys-sdk/src/usb/hid/ctap_hid.h:116-117`
(`CAPFLAG_WINK 0x01`, `CAPFLAG_CBOR 0x04`) and `hid.c:451`
(`resp->capFlags = CAPFLAG_WINK | CAPFLAG_CBOR`).

**Where the correction lives:** `firmware/src/ctap_hid.rs:108-162` — the doc
comment now carries a "## How strong that claim is — measured, and weaker than
it reads" section that states all of the above; the value is
`CTAPHID_INIT_CAP_FLAGS: u8 = 0x05` at `:163`. Do not simplify it back to a
single `0x04` on the plan's reasoning. Commit `ca88681`.

**Open:** whether any browser acts on `capFlags` at all. Unknown, and not
knowable from this machine.

---

### C4 — `vendor41` has **fourteen** sub-commands, all with real arms

**The plan said** (US-1516): "All 12 sub-commands are `NOT_ALLOWED` stubs
(`vendor41.rs:656`; `PENDING` is an empty slice)."

**What is true:**

- There are **fourteen** sub-commands, not twelve — `apps/fido/src/vendor41.rs:560`
  (`enum Subcommand`, `RSKEY_VENDOR_MSE` 1 … `RSKEY_VENDOR_AUDIT_CONFIG` 14) and
  `Subcommand::ALL: [Subcommand; 14]` at `:600`.
- **Every one has a real arm** in `handle_subcommand` — 14 match arms,
  `:1146-1212`.
- **The empty `PENDING` was honest, not a tell.** `PENDING` is the *stub set*:
  `vendor41.rs:689` `pub const PENDING: &[Subcommand] = &[];` — "the subset that
  currently answers `NOT_ALLOWED`". An empty slice means **no stubs remain**. It
  has been empty since US-170…US-175. The plan read a correct empty slice as
  evidence of stubs.
- The dishonesty was one layer up: prose that outlived the stubs. Both twins'
  `0x41` arms said "every sub-command is a `NOT_ALLOWED` stub", and
  `vendor41::authorize`'s doc said the twelve "do not reach it" — when they are
  its main callers.

**Evidence** (executed + read): executed —
`every_subcommand_is_dispatched_on_the_device_path` in
`apps/fido/tests/vendor41.rs` drives **`device_app::FidoApp`** (the twin the
RP2350 runs) over all fourteen. Read — `vendor41.rs:770` `decision()` carries one
`SubcommandDecision` row per sub-command, 14 rows, each naming the story that
wrote the arm, the serving function, and what authorises a request arriving with
**no** token.

**Where the correction lives:** `apps/fido/src/vendor41.rs:770+` (`decision()`)
and the corrected twin prose in `apps/fido/src/app.rs` and
`apps/fido/src/device_app.rs`. Commit `03eae03`.

**Open:** none. Note the test asserts `!= 0x01`, not `!= NOT_ALLOWED` — measured:
Export legitimately answers `0x30` for a sealed export window.

---

### C5 — §1.2's failure-class table misroutes a page-side block into a firmware bug

This was the epic's **gate** (§1.2, and the §5 decision tree built on it).

**The plan said** (§1.2): the discriminating evidence "is one line — the
DOMException name", and the table row "`SecurityError` | page-level: third-party
iframe without `publickey-credentials-create` delegation". §5 then says that
branch means "EPIC STOPS. Not a firmware bug."

**What is true:** in Chrome 145, an undelegated cross-origin iframe yields
**`NotAllowedError` at ~1 ms**, with the message "The
'publickey-credentials-create' feature is not enabled in this document…". It is
the *same exception name* as a device-level timeout and the *same message* as a
top-level Permissions-Policy denial. A `SecurityError` did occur — but only in a
control (an IP-literal RP ID) that the real passkey flow cannot produce.

**The consequence, stated plainly:** anyone following the plan's stated method —
catch the exception, read `.name`, pick the row — reads a cross-origin-iframe
block as "device-level → go fix the firmware", and chases a firmware bug that
does not exist. The plan's gate would have mis-routed a page-side failure *into*
this epic rather than stopping it.

**The working discriminator is `elapsedMs` + message**, not the name:
~1 ms + "feature is not enabled in this document" → page-side, the device was
never addressed; elapsed ≈ the full `timeout` → device-side. A 10,000-fold
latency gap, available from any `catch` block with no debugger.

**Evidence** (executed): Chrome 145.0.7632.6 (Chrome for Testing, headed, stock
flags) across four controlled cells plus a control, each a real
`navigator.credentials.create()` with a real user activation; A/B differ by one
response header, C/D by one iframe attribute and nothing else. Raw output and
launch flags: `docs/webauthn-browser-failure-class-us1520.md` §1.1 and its
appendix.

**Where the correction lives:** that evidence document. The hazard is recorded
here because the *plan* is what needs the warning, and the plan is gitignored.

**Open:** the federated-iframe hypothesis is still live and still untested — it
cannot be reached without a logged-in session. When someone with a session runs
it, the measurement to take is **whether the rejection arrives in ~1 ms or after
the full timeout**, not the exception name.

---

### C6 — §6's dependency graph is physically impossible as drawn

**The plan said** (§6): US-1505 (`CTAPHID_CANCEL`) and US-1506 (keepalive
protocol) are **parallel feeders into US-1511**, drawn alongside the
`US-1502 → US-1508 → US-1509 → US-1510 → US-1511` chain rather than downstream of
it.

**What is true:** before US-1509, a `CANCEL` **could not reach the device at
all** during a consent window, so an arm for it could not have been written and
verified first. US-1505 is necessarily downstream of US-1509, not parallel to it.

**Evidence** (read + executed on hardware):

- Read, at base `2c29d29`: `firmware/src/tasks.rs:538` is the serve loop's
  **only** inbound read (`hid_out.read(&mut report).await`; `grep -c
  "hid_out.read()"` on that file returns 1). `dispatch_hid_cmd(` is at
  `tasks.rs:621` and is awaited **inline** in that same loop body. The consent
  window is a **nested `loop {` at `tasks.rs:818`** *inside* `dispatch_hid_cmd`
  (opened by `begin_window(tag, CTAP_TOUCH_WINDOW_MS)` at `tasks.rs:814`), and it
  only writes keepalives and re-drives the command — it never reads. No frame is
  received for the whole 30 s window, so no dispatch arm could fire.
- Executed on hardware, `docs/webauthn-discovery-baseline.md` part (b): during
  the window, `open-channel PING` and `CTAPHID_CANCEL` were both **NEVER
  WRITTEN** — the write blocked and was abandoned at its 3.0 s deadline,
  `[Errno 110] Connection timed out`, in **all four runs**. The one `INIT` that
  did get written went into a buffer the device never drained. Finding F2 there:
  "during the consent window the device does not read the HID OUT endpoint at
  all".

**Open:** none for the graph.

---

### C7 — The CTAP2 status table: six wrong values, in three private copies

**Not in the epic at all.** Found by US-1528 while executing what US-1528 was
actually about.

**What was wrong** (`apps/fido/src/ctap2.rs`, `Ctap2Response`):

| variant | was | is | note |
|---|---|---|---|
| `LockRequired` | `0x07` | `0x0A` | also collided with `Ctap2Command::Reset = 0x07` |
| `InvalidChannel` | `0x08` | `0x0B` | |
| `UnsupportedOption` | `0x2A` | `0x2B` | `0x2A` is the **withdrawn** `NO_OPERATION_PENDING` |
| `InvalidOption` | `0x2B` | `0x2C` | **the bug** |
| `KeepAliveCancel` | `0x2C` | `0x2D` | see C1 |
| `NoOperationPending` | `0x29` | *removed* | `0x29` is the **withdrawn** `NOT_BUSY` — a different withdrawn code |

**The consequence.** Every `InvalidOption` this firmware returned was decoded by
every client as `UNSUPPORTED_OPTION` — a different sentence ("you named a value
we do not support" vs "you named a value that is malformed for a parameter we do
support"). There are **ten producer sites** today:
`apps/fido/src/device_core.rs` ×3, `apps/fido/src/app.rs` ×3,
`apps/fido/src/vendor41.rs` ×4 — on both twins and on the RP2350.

**The three duplicate tables.** The same data was privately transcribed three
times, and **two of the three carried identical mistakes**, which is what made it
invisible:

- `apps/fido/src/ctap2.rs` — `Ctap2Response`: six wrong (above).
- `apps/fido/src/hid.rs` — `CtapHidError`: two wrong, the same `0x07`/`0x08`
  pair. Now `:75-76`.
- `apps/fido/src/lib.rs` — `FidoError::to_ctap_error` (`:354`): **one** wrong,
  `InvalidChannel => 0x08`, now `0x0B` at `:384`.

So the accurate count is **nine wrong instances across three tables, six
distinct values** — not "six across three". Note also that `FidoError` has **no
`InvalidOption` variant at all** (the enum at `apps/fido/src/lib.rs:288-347`), so
`to_ctap_error` could never express that status; and `FidoError::UnsupportedOption`
was already `0x2B`, i.e. *correct* in that table while wrong in
`Ctap2Response`. The three tables did not uniformly agree with each other — two
of them agreed with each other and with neither the reference nor the third.

**Evidence** (executed + read):

- Executed `fido2` 2.2.1's `CtapError.ERR` at runtime: `LOCK_REQUIRED 10`
  (`0x0A`), `INVALID_CHANNEL 11` (`0x0B`), `UNSUPPORTED_OPTION 43` (`0x2B`),
  `INVALID_OPTION 44` (`0x2C`), `KEEPALIVE_CANCEL 45` (`0x2D`),
  `PIN_TOKEN_EXPIRED 56` (`0x38`), `UP_REQUIRED 59` (`0x3B`), `UV_BLOCKED 60`
  (`0x3C`), and `NO_OPERATION_PENDING` / `NOT_BUSY` return **no member at all**.
- Read: `../pico-fido2/src/fido/ctap.h:174-176` agrees on all three of
  `0x2B`/`0x2C`/`0x2D`; `../pico-fido2/pico-keys-sdk/src/usb/hid/ctap_hid.h:157-158`
  agrees on `0x0A`/`0x0B`.
- **`PinTokenExpired = 0x38` is correct and was left alone.** It is absent from
  the C header (`ctap.h` runs `PIN_POLICY_VIOLATION 0x37` straight to
  `REQUEST_TOO_LARGE 0x39`) but defined by `CtapError.ERR`, and the library is
  the decoder. Aligning to the C header would emit a byte every client reads as
  `REQUEST_TOO_LARGE`.

**Where the correction lives:** `apps/fido/src/ctap2.rs:58-172` (the table's doc
comment carries the whole derivation, including why `NoOperationPending` was
removed rather than re-valued), and **`apps/fido/tests/status_table.rs`** — 12
tests, pinned with hand-transcribed literals rather than values derived from the
table under test, which would be vacuous. Executed for this document:

```
$ cargo test -p fapico2-fido --target x86_64-unknown-linux-gnu --test status_table
test result: ok. 12 passed; 0 failed
```

Commit `8048e30`; falsification recorded there — restoring the pre-fix table
byte-for-byte fails 16 tests across 5 files.

**Open:** none.

---

### C8 — A **fourth** private copy: the CTAPHID *command* table was transposed

**Not in the epic.** Found by US-1528's follow-up, in the same file it had just
corrected.

**What was wrong:** `apps/fido/src/hid.rs` read
`CtapHidCommand { Keepalive = 0x03, Msg = 0x10, … }`. The reference has
**`MSG = 0x03`** (CTAP1/U2F over HID) and **`CBOR = 0x10`** (CTAP2). The two were
swapped, so the table described a protocol that does not exist. And there is no
CTAPHID keepalive *command* at all: `0x3B` is a CTAP2 **status** byte inside a
CBOR response. `Keepalive` is **dropped from the enum**, not re-valued.

**Why it survived review:** the enum is dead code (nothing outside `hid.rs`
names it), and the wrong entry was *named* `Keepalive` — an enum of "commands"
containing an entry that is not one reads as a complete list of commands, and
`0x03` beside it looks plausible.

**Evidence** (executed): `fido2.hid.CTAPHID` in `fido2` 2.2.1, read by running
the enum rather than grepping a header —
`{'PING':1,'MSG':3,'LOCK':4,'INIT':6,'WINK':8,'CBOR':16,'CANCEL':17,'ERROR':63,
'KEEPALIVE':59,'VENDOR_FIRST':64}`. Note the library *does* carry a `KEEPALIVE`
member at `0x3B`; it is a value the host decodes on the **inbound** path
(`fido2/hid/__init__.py:223-231`), never a command the host sends, which is
precisely why an entry named `Keepalive` reads as legitimate in a command enum.

**Where the correction lives:** `apps/fido/src/hid.rs:1-47` (doc comment) and the
enum; pinned by `the_ctaphid_command_table_matches_the_reference` in
`apps/fido/tests/status_table.rs:366`, which also asserts no member claims `0x3B`
and cross-checks the firmware's live constants in `firmware/src/ctap_hid.rs`.
Commit `ba26fc5`.

**Open:** none.

---

### C9 — `makeCredUvNotRqd` was a hard-coded lie, and the epic never mentions it

**Not in the epic.** `grep -n makeCredUvNotRqd docs/tasks/EPIC-webauthn-browser-discovery.md`
returns **nothing**. Found by the two-board A/B probe, not by the plan — board B
(the C reference) answered `makeCredUvNotRqd: False` and board A answered `True`,
which is the shape of a bug, not a difference.

**What was true at base `2c29d29`:** `apps/fido/src/ctap2.rs:414`
`options.push(("makeCredUvNotRqd", true)).ok();` — seeded `true` on the reasoning
recorded in its own comment: *"makeCredential does not require UV when no PIN is
set"*. **CTAP 2.1 §6.1.3 does not mean that.** The option is "support for making
non-discoverable credentials without requiring user verification"; absent/false
means the device requires UV for that "regardless of the parameters the platform
supplies". Nothing in it is scoped to the no-PIN state.

So on a device with a PIN set — the shipped state — the advertisement licensed a
request the device refuses: both twins answer a bare `makeCredential` with no
`pinUvAuthParam` and no `uv` option with `0x36 PUAT_REQUIRED` (the §8.1 gate at
`apps/fido/src/device_core.rs:854` / `apps/fido/src/app.rs:1329`, which is the C
reference's branch at `../pico-fido2/src/fido/cbor_make_credential.c:404`).
Measured on both twins, device path included.

**It is not idle.** `fido2/client/__init__.py:664`, inside
`_should_use_uv`, decides whether to ask for a PIN before a `makeCredential`
from this option **by name** —
`elif mc and uv_configured and not info.options.get("makeCredUvNotRqd"):`. With
`true`, that branch is skipped, `_should_use_uv` returns `False`, and the client
sends `opts = None` (`fido2/client/__init__.py:833`) — straight into the refusal
above.

**Evidence** (executed + read): the A/B measurement in
`docs/webauthn-discovery-ab.md` (board A `makeCredUvNotRqd: True`, board B
`False`); executed tests `apps/fido/tests/make_cred_uv_not_rqd.rs`, 8 tests on
both twins asserting **coherence per state** (advertised `true` ⇒ the bare
request must be served; advertised `false` ⇒ it must be refused) rather than
option presence. Four of the eight fail on the pre-fix source. Commit `75066bc`.

**Where the correction lives:** `apps/fido/src/ctap2.rs:628`
(`make_cred_uv_not_rqd(pin_set, always_uv) = !pin_set && !always_uv`), called from
both twins' `handle_get_info` (`apps/fido/src/device_core.rs:2119`,
`apps/fido/src/app.rs:1203`); the bare `default()` seeds the **safe** value
(`false`) at `apps/fido/src/ctap2.rs:694`, so a default can never over-claim. The
gate itself is unchanged — weakening it would move the PIN/UV posture US-907 and
US-921 own.

**Open — and this one matters.** **US-1529 is not hardware-proven.** See
"Human-gated and therefore not delivered" below.

---

### C10 — `pinUvAuthToken` (US-1512): the epic had it; what was new was a code-comment inversion

This entry records a **correction to the brief's own framing**.

**The brief said** US-1512 was "not in the epic at all".

**That is wrong.** The epic carries the finding verbatim and correctly:
§2.7 "`pinUvAuthToken: true` is a hard-coded lie. `ctap2.rs:409` sets it
unconditionally, while `clientPin` is correctly recomputed from real PIN state
(`device_core.rs:2019`) … **Verified**", restated in §4.4, and raised as a Phase D
story (`US-1512 — pinUvAuthToken / clientPin coherence`). Checked at base
`2c29d29`: `apps/fido/src/ctap2.rs:409` was
`options.push(("pinUvAuthToken", true))` with no recomputation anywhere, and
`apps/fido/src/device_core.rs:2019` did set `clientPin` from
`pin_state.pin_hash.is_some()`. **The epic's claim held**, and its line citations
were exact.

What the epic could not have caught, because the claim was introduced *by* the
epic's own US-1512 implementation and then reviewed only by reading: the doc
comment on `pin_uv_auth_token_available` asserted that once the durable lockout
flag latches, "every PIN leg refuses … a client reads `true`, mints a token, and
is then refused at the first command". **`device_core.rs` does the opposite**,
thirteen lines below the reference to it: the `0x05`/`0x09` success path clears
`blocked`, `needs_power_cycle` and `new_pin_mismatches` **and** mints the token in
the same breath. The paragraph contradicted itself four sentences later. The
*value* `!(blocked || needs_power_cycle)` was right and stayed; the *reasoning*
was not.

**Evidence** (executed): driven through latch → correct PIN on **both** twins,
each giving `pinUvAuthToken: false` → correct PIN `0x00` → `true`, with a non-empty
token body at CBOR key `0x02`. Now two permanent tests,
`a_correct_pin_restores_the_route_it_withdrew` (host twin) and
`device::device_correct_pin_restores_the_route_it_withdrew` (the twin the RP2350
runs). Falsified before committing: deleting the latch-clearing lines turns the
device test red while the host one stays green. Commit `1c3feba`.

**A related inversion in the same review** (`0376e2e`): a comment claimed
`ClientPin.is_token_supported()` had a single uv-gated call site, making the bit
wire-inert for `fido2` 2.2.1. It has **three**, and only one is uv-gated — the
grep behind the claim searched the `pinUvAuthToken` string literal rather than the
`is_token_supported` wrapper that consumes it. Again: **read, not executed.**

**Where the correction lives:** `apps/fido/src/ctap2.rs:491-560` (the rule and
the invariant that is actually checkable — the advertisement and the token route
agree, in both directions), `apps/fido/tests/pin_uv_advert.rs`.

**Open:** none for the value, and it is proven on the twin that matters — the
measurement above ran through `device_app::FidoApp`/`device_core.rs`, not the
host twin. What is *not* done is a re-probe of the options map on the **shipped
board** with the US-1529 build, which is blocked by the post-flash hang below.

---

### C11 — §7's Definition of Done lists **nine** items

**The brief said** the epic "claims §7 has eight Definition-of-Done items; it
lists nine."

**Half of that does not hold up.** §7 of the plan does list **nine** numbered
items (plan lines 511, 515, 517, 519, 520, 521, 522, 524, 526) — that part is
right. But the plan **nowhere claims eight**. `grep -ni "eight"` over the plan
returns nothing at all (exit 1). The only `8` in the plan is
`## Phase D — Advertisement and conformance defects (8 points)` at line 391,
which is a **points** total for Phase D, not a Definition-of-Done count, and is
unrelated.

So the checkable correction is the count only: **nine items, of which items 3
and 5 are now known to have been specified wrongly** (see C2 and C3 — DoD 3 says
CANCEL "closes the window with a zero-length keepalive", and item 5 says
`capFlags` must read as "CBOR + WINK" under both conventions, which it now does
but for parity reasons rather than the stated ones). Item 7 (real sites, cold
boot, real hardware) is human-gated and undelivered.

**Open:** items 6 and 7 remain open; see below.

---

## The audit — twelve claims that inverted

Every one of these was a confident claim that came out **the other way** when it
was executed instead of read. Six were statements in the plan; the rest were in
code comments or in this epic's own evidence documents, which is the same defect
class in a different place.

| # | the claim | where | settled by | now at |
|---|---|---|---|---|
| 1 | `CTAP2_ERR_KEEPALIVE_CANCEL` is `0x2C` | plan, US-1506 | **executed** (`CtapError.ERR`) + read | C1 |
| 2 | a `CANCEL` must be answered with a zero-length keepalive | plan, US-1505 + §7.3 | **executed** (matcher, synthetic frames) + read | C2 |
| 3 | `capFlags = 0x04` is the likely discovery bug | plan, §3 | **executed** (two boards) | C3 |
| 4 | an undelegated third-party iframe yields `SecurityError` | plan, §1.2 (the gate) | **executed** (Chrome 145) | C5 |
| 5 | 12 `vendor41` sub-commands, all `NOT_ALLOWED` stubs | plan, US-1516 | **executed** (14 over `device_app::FidoApp`) | C4 |
| 6 | US-1505/US-1506 can be built in parallel into US-1511 | plan, §6 | **read** (`tasks.rs:538` / `:621` / `:818`) + **executed** on hardware (`ETIMEDOUT`) | C6 |
| 7 | the CTAP2 status table's values | code, `apps/fido/src/ctap2.rs` | **executed** (`CtapError.ERR`) + read | C7 |
| 8 | `CtapHidCommand`: `Keepalive 0x03`, `Msg 0x10` | code, `apps/fido/src/hid.rs` | **executed** (`fido2.hid.CTAPHID`) | C8 |
| 9 | `makeCredUvNotRqd: true` is correct because no PIN means no UV | code, `apps/fido/src/ctap2.rs` | **executed** (two boards + 8 coherence tests) | C9 |
| 10 | once locked, "every PIN leg refuses" a minted token | code comment, `pin_uv_auth_token_available` | **executed** (both twins, latch → correct PIN) | C10 |
| 11 | `is_token_supported()` has one uv-gated call site | code comment | **grep → 3, one uv-gated** | C10 |
| 12 | an identical 156-byte `MakeCredential` answering `0x3B` pre-epic and `0x12` on this branch is "the epic's central failure: a browser cannot register a passkey" | evidence, `docs/webauthn-discovery-ab.md` PROBE 5 | **executed** bisect over `ea298a6..HEAD`: every commit in the range answers `0x12`, the pre-epic baseline included. Commit `0e532e8` | — |

Two further items in the same class are worth knowing because they are the
*shape* of the failure rather than a single claim:

- **`ClientPin.is_token_supported()` — #11 — and #10 are the same error**: a
  grep standing in for an execution, where the pattern searched did not match the
  code that consumes it.
- **The emulator-parity gate never ran.** `firmware/src/lib.rs` gates `emul_hid`
  on `feature = "emulation"` alone, and CI's single firmware test step is
  `cargo test -p fapico2-firmware --lib`, which resolves `default = ["device"]`.
  Measured: **78** tests under `device`, **84** under `device,emulation`, and the
  delta is exactly the six parity tests. So the plan's DoD item 6 ("the emulator
  and the board answer identically") had **no executed evidence anywhere**.
  Separately, the acceptance runner's exit code was `return 1 if machine_fail
  else 0` while two browser cases were filed `gate: "machine"` regardless, so a
  browser-less run reported success over both. Commit `37aec06`.

**The takeaway, and the reason this table exists:** claims about *this firmware's
own logic* held up when read (§2.2, §2.3, §4.4 and the epic's `file:line`
citations were accurate at base `2c29d29` — checked). Claims about *what a client
does* inverted every time. Read the client's decoder; do not read a header about
the client.

---

## Human-gated, and therefore not delivered

None of these are unfinished work; they are ceremonies that need a body, a
logged-in account, or a finger. **No part of this branch is blocked on them, and
no part of this branch delivered them.**

| item | what it needs | where the gap is stated |
|---|---|---|
| **US-1520, device-side half** | our board attached to USB | `docs/webauthn-browser-failure-class-us1520.md` §0.1 — the run had only the C reference board, so "every firmware-side row of the table is untestable in this run". §0.2 also records a stale headless Chrome from an earlier experiment holding the reference's `/dev/hidraw13` for the whole session, so the device-enumeration readings there should be re-taken with that process gone. |
| **US-1527** — real-site registration | a logged-in account on X + two further sites, from a cold boot, at a changed VID/PID | epic §"US-1527"; needs a human by design — that is why it was split out of US-1518. |
| **US-1503** — deliberate physical button press during an open window | a finger | `docs/webauthn-discovery-baseline.md` part (d): "NOT MEASURED — requires human. No finger was placed on the board, nothing was simulated, and no number is reported here." A scripted result would be worse than none. |
| **US-1529** — flash/USB proof of the `makeCredUvNotRqd` fix | a successful flash, then a re-probe of the options map on the shipped board | see the post-flash hang below. Rests on host evidence only. |

Also open, and not human-gated: **DoD item 6** (emulator/board parity) is now
*gated in CI* (`37aec06`) but was never executed against the RP2350 itself; and
**US-1522's** federated-iframe in/out question stays unresolved pending a session.

---

## The post-flash hang — 2 of 2, still open

**Measured.** `scripts/bootsel.py --bootsel --flash` reports success — the
`REBOOT` (BOOTSEL) APDU returns `9000`, the RP2350 volume mounts, the UF2 is
copied, and the script prints "done: firmware flashed, device in app mode." —
and **the board then never re-enumerates**. Polled 50 s: absent from `lsusb`, no
bootrom device, no mass-storage volume. **Reproducible: two attempts out of two.**

**Pre-existing.** The boot→enumeration path is unchanged by this branch:
`firmware/src/main.rs` is byte-identical to base `2c29d29`
(`git diff --stat 2c29d29..HEAD -- firmware/src/main.rs` is empty);
`firmware/src/boot.rs` gained only the `PENDING_UP` static and no logic;
`apps/rescue/src/lib.rs` gained only a comment. `platform/src/usb.rs` did change
(US-1515), but the change is inside a **control-request handler** — the CTAP
`SET_REPORT` data-stage wiring — which cannot run before the device has already
enumerated. So the branch is not the cause.

**No post-mortem read channel.** The only instruments that can see what the boot
is doing are an SWD debugger (attach one and `OTP_DATA_RAW` reads return
`0xFFFFFFFF`, `read_otp_key_1()` reads that as "no key", and `fatal_boot` fires
**before USB is constructed** — `AGENTS.md` "Hardware warnings") or a physical
power cycle. `AGENTS.md` forbids the debugger for exactly this failure mode, so
the hang is, today, only diagnosable by a human holding the board.

**Where it is tracked.** A separate epic, `BOOT-FREEZE-POST-FLASH`
(US-1301…US-1312), exists for the investigation — **and it is in
`docs/tasks/`, so it is gitignored too.** Its pivot story, US-1301, is to
separate "flash then reboot" from "debug then reboot", which `AGENTS.md`
records as the same observational event until a run distinguishes them. **If
`docs/tasks/` is ever cleaned up, that epic must be carried forward somewhere
durable — this document is not a substitute for it.**

**Still open.** Not diagnosed. Two of two.

---

## Where each correction lives, at a glance

| correction | file | anchor |
|---|---|---|
| C1 keepalive-cancel byte | `firmware/src/ctap_hid.rs` | `:106` |
| C1 + C7 `apps/fido` side | `apps/fido/src/ctap2.rs` | `:58-172` |
| C2 no CANCEL ack | `firmware/src/hid_serve.rs` | `:914-1006`, rationale `:927-953` |
| C3 `capFlags` = `0x05` | `firmware/src/ctap_hid.rs` | `:108-163` |
| C4 fourteen `vendor41` decisions | `apps/fido/src/vendor41.rs` | `:560`, `:600`, `:689`, `:770`, `:1146-1212` |
| C5 failure-class discriminator | `docs/webauthn-browser-failure-class-us1520.md` | §1.1, §1.2 |
| C6 serve-loop structure | `firmware/src/hid_serve.rs` (post-fix) / base `tasks.rs:538,621,818` | — |
| C7 + C8 status and command tables | `apps/fido/tests/status_table.rs` | 12 tests, all green |
| C9 `makeCredUvNotRqd` | `apps/fido/src/ctap2.rs` | `:628`, `:694`; `device_core.rs:2119` |
| C10 `pinUvAuthToken` | `apps/fido/src/ctap2.rs` | `:491-560`; `tests/pin_uv_advert.rs` |
| flash ratchet (epic US-1519) | `.github/workflows/ci.yml` | `:47-91` — `FIRMWARE_FLASH_BUDGET_KIB: 1536` |

---

## The evidence documents

Not restated here. Read them for the measurements; read this file for what the
plan got wrong.

- [`webauthn-discovery-baseline.md`](webauthn-discovery-baseline.md) — first
  hardware baseline (US-1501). Parts (a)(b)(c) machine-measured; part (d) is
  human-gated.
- [`webauthn-discovery-ab.md`](webauthn-discovery-ab.md) — the two-board wire
  comparison, Rust board vs the `pico-fido2` C reference (US-1521). Source of C3
  and C9.
- [`webauthn-browser-failure-class-us1520.md`](webauthn-browser-failure-class-us1520.md)
  — the browser failure-class capture (US-1520). Source of C5.
- [`webauthn-acceptance-us1518.md`](webauthn-acceptance-us1518.md) — the
  acceptance harness results (US-1518). Machine cases and the human/machine
  split.
- [`size-report.md`](size-report.md) — the flash/RAM budget (US-1519).

**A caution about the first one.** `docs/webauthn-discovery-baseline.md` carried
a column of integer option ids (`clientPin 0x06`, `pinUvAuthToken 0xC`, `uv
0x03/0x0E`) that **no run ever observed**: the probe indexed the options map by
CTAP2 integer id, and this device emits **string** keys, so all seven lookups
returned *absent* — and seven-of-seven absent was not treated as a fault. The
document then filled the column in from spec knowledge, which is the one defect
class this epic's evidence discipline exists to prevent. The probe now looks
options up **by name** and treats an all-absent result as a loud anomaly that
exits `4`. Commit `44ade5f`. **If you find an unsourced number in an evidence
document on this branch, treat it as a defect until you find the archive it came
from.**
