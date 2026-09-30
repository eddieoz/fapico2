"""US-105 (EPIC `PICOForge-COMPAT`): PicoForge end-to-end detection smoke test.

PicoForge classifies a token in two steps
(`picoforge/src/hal/fido/mod.rs`, `picoforge/src/hal/firmwares/mod.rs`):

1. enumerate the first HID device on usage page ``0xF1D0``,
2. run CTAPHID ``INIT`` and then CTAP2 ``GetInfo`` (``0x04``), and exact-match
   the returned AAGUID (getInfo key ``0x03``) against a three-entry table —
   RS-Key ``2479C7BF6B3056839EC80E8171A918B7``, pico-fido / LK-ONE
   ``89FB94B706C936739B7E30526D968145``, anything else ⇒ "Unknown".

Before this EPIC, fapico2's AAGUID matched no entry, so the app silently fell
through to its pico-fido profile and hid the OpenPGP applet. This module
drives steps 2's commands over the emulated CTAP-HID transport and pins the two
values that decide the outcome, so a future AAGUID or version regression fails
here instead of degrading silently in a desktop app nobody can test against.

## What this test actually proves — read before citing it as hardware evidence

This is an **[EMU]** test. It runs against the `fapico2-emulation` host binary
(`--target x86_64-unknown-linux-gnu`, `feature = "emulation"`), reached through
`tests/harness/hid_emul.py`, which splices a plain TCP socket into
python-fido2's HID backend. It is a **regression guard on the wire format of two
getInfo keys**, not a hardware qualification result.

**Covered:** the CTAPHID framing (INIT nonce echo, CBOR command/response), and
the literal bytes of getInfo keys ``0x03`` and ``0x0E`` as they appear on the
wire, decoded from the raw CBOR rather than through a library accessor. The
framing is covered as *fapico2 and this consumer agree on it*, **not** as
CTAP 2.1 spec conformance — the INIT payload omits the status byte the spec
prescribes, and the assertion below is deliberately offset to match. See the
long note in `_detection_get_info`.

**NOT covered — do not read a green run as any of the following:**

* **Not hardware.** No RP2350, no USB. The device and emulation paths happen to
  share one `Ctap2Info::default()` (`apps/fido/src/ctap2.rs`), which is what
  makes the emulation value meaningful for these two keys — but that is a code
  fact, not something this test demonstrates. A device-only divergence in
  `device_core.rs::handle_get_info` would not be caught here.
* **Not enumeration.** Step 1 of PicoForge's detection is *not* exercised. The
  harness's `hid_emul.get_descriptor()` returns a synthetic
  `HidDescriptor(None, 0x00, 0x00, 64, 64, "Pico-Fido", "AAAAAA")` — usage
  page **0x00**, not ``0xF1D0``. There is no USB descriptor and no usage page on
  a TCP socket, so "first device on usage page 0xF1D0" has no analogue here and
  is not asserted.
* **Not the serial.** US-103's 8-digit USB serial is likewise unexercised; the
  shim reports a constant `"AAAAAA"` and never asks the emulator.
* **Not PicoForge itself.** The detection *table* is mirrored here as a literal
  (see `RSKEY_AAGUID`) so a change to the app's table shows up as a failure
  here, but no part of the application runs.
* **Not the AAGUID override.** See the note on
  `test_device_is_classified_as_rskey`.

## Why the override is not asserted here (EPIC §8 gate 7)

Gate 7 asks that the US-101 AAGUID override test run for both the default and
the overridden build. That is already satisfied, deliberately, by
`apps/fido/tests/aaguid_build.rs` (US-101), which shells out to two real
`cargo build`s and asserts the AAGUID bytes in the resulting rlib track
`FAPICO2_AAGUID_HEX` in **both** directions.

Repeating it here would not be cheap, and would be unfalsifiable: the emulator
is a *session-scoped external process*, not a pytest fixture, so an
"overridden build" assertion inside a running test could only re-build a crate
in-process — it would no longer be talking to the device-under-test. This
module therefore pins the **default** build's AAGUID, which is the value a
stock `run_tests.sh` emulator serves, and leaves the override to the test that
can actually rebuild and inspect the artifact.
"""

import re
from pathlib import Path

import pytest
from fido2 import cbor
from fido2.hid import CTAPHID

# CTAP2 getInfo map keys this test pins.
KEY_AAGUID = 0x03
KEY_FIRMWARE_VERSION = 0x0E

# CTAP2 getInfo (0x04) as a single-byte CTAPHID CBOR command payload.
CTAP2_CMD_GET_INFO = b"\x04"

# CTAPHID success status byte (CTAP spec §11.2.4); 0x00 == OK.
CTAP2_OK = 0x00

# PicoForge's RS-Key profile entry (`picoforge/src/hal/types.rs:251`,
# `RSKEY_AAGUID`). Exact-matched, upper-case, no separators.
RSKEY_AAGUID = "2479C7BF6B3056839EC80E8171A918B7"

# fapico2's own published AAGUID: the ASCII bytes of "fapico2", a NUL, padding,
# and a version word. The *default* since 2026-09-28 — the RS-Key value above
# is now reachable only as the `FAPICO2_AAGUID_HEX` build override, which is
# how a build is aimed at a client that has not yet been taught ours.
FAPICO2_AAGUID = "66617069636F3200000000000000 0002".replace(" ", "")

# `format_firmware_version` (`picoforge/src/hal/fido/mod.rs`) branches on
# `raw > 0xFFFF`: strictly greater renders "major.minor.patch", otherwise
# "major.minor". fapico2 packs `(major << 8) | minor`, so it MUST land at or
# below 0xFFFF or the consumer reads a three-component version off a two
# component encoding. 0xFFFF itself takes the two-component branch, hence
# `<=` and not `<`.
FIRMWARE_VERSION_TWO_COMPONENT_MAX = 0xFFFF

# A CTAPHID INIT nonce: arbitrary 8 bytes the authenticator must echo.
INIT_NONCE = b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"

# CTAPHID INIT reply payload length: nonce(8) + cid(4) + versionInterface(1) +
# versionMajor(1) + versionMinor(1) + versionBuild(1) + capabilityFlags(1).
INIT_REPLY_LEN = 17

# INIT capabilityFlags bit: "the authenticator implements CTAP2 CBOR commands"
# (CTAP 2.1 §11.2.9, bit 2). GetInfo is only reachable when it is set — this is
# the bit that says the CBOR exchange the rest of this module performs is
# available at all, so assert it rather than merely echoing a nonce.
INIT_CAP_FLAG_CBOR = 0x04

# Channel identifiers the HID layer must never allocate: CTAPHID_BROADCAST
# (0xFFFFFFFF, INIT is the only command allowed on it) and CTAPHID_RESERVED
# (0x00000000, accepts nothing). A reply carrying either would mean INIT
# handed back a channel the next command could not use.
INIT_CID_RESERVED = b"\x00\x00\x00\x00"
INIT_CID_BROADCAST = b"\xff\xff\xff\xff"


def _workspace_firmware_version():
    """The packed firmwareVersion this build *should* report.

    Read from the workspace manifest rather than hard-coded, so bumping
    `[workspace.package] version` does not turn this into a failing test that
    nobody is sure is a real regression. The device constant is
    `pack_firmware_version(env!("CARGO_PKG_VERSION"))`
    (`apps/fido/src/lib.rs`), i.e. `(major << 8) | minor`, patch dropped.
    """
    manifest = Path(__file__).resolve().parents[2] / "Cargo.toml"
    text = manifest.read_text(encoding="utf-8")
    workspace_package = text.split("[workspace.package]", 1)
    assert len(workspace_package) == 2, (
        "no [workspace.package] section in %s — cannot derive the expected "
        "firmwareVersion" % manifest
    )
    match = re.search(
        r'^\s*version\s*=\s*"(\d+)\.(\d+)\.(\d+)"',
        workspace_package[1],
        re.MULTILINE,
    )
    assert match, (
        "no MAJOR.MINOR.PATCH version in [workspace.package] of %s — "
        "pack_firmware_version would const-panic on such a manifest" % manifest
    )
    major, minor, _patch = (int(g) for g in match.groups())
    return (major << 8) | minor


def _detection_get_info(device):
    """Run PicoForge's detection handshake and return the decoded getInfo map.

    Mirrors `picoforge`'s own sequence: CTAPHID ``INIT`` (to establish the
    channel), then CTAPHID ``CBOR`` carrying the single-byte CTAP2
    ``GetInfo`` (``0x04``). The response is decoded from the raw CBOR with
    python-fido2's decoder rather than through a typed accessor, because the
    point is the bytes on the wire. `decode_from` is used (not `decode`)
    because CTAPHID pads short reports to 64 bytes.
    """
    init_reply = device.send_data(CTAPHID.INIT, INIT_NONCE)

    # --- The INIT payload layout, read at offset 0. DELIBERATE. -----------
    #
    # CTAP 2.1 §11.2.7.1 specifies the INIT reply payload as
    # `status(1) || nonce(8) || newChannelId(4) || ...`, i.e. the nonce at
    # payload offset **1**. fapico2 instead returns the 17-byte payload with
    # **no leading status byte** — `nonce(8) || cid(4) || versionInterface ||
    # versionMajor || versionMinor || versionBuild || capabilityFlags` — so the
    # nonce really does start at offset 0, and the assertion below is right.
    #
    # This is not an emulation artefact: both paths build the identical
    # status-less 17-byte reply. See `fapico2_firmware::hid::serve_init` in
    # `firmware/src/emul_main.rs` and the INIT branch of the CTAPHID serve
    # loop in `firmware/src/tasks.rs` (anchored by function, not line number,
    # because these move).
    #
    # The consumer agrees with the status-less layout, which is why this must
    # NOT be "corrected": `picoforge::hal::transport::fido::HidTransport::
    # init_channel` matches the nonce at report `[7..15]` and reads the new
    # channel at report `[15..19]`. Report offset 7 is the end of the
    # `cid(4) || cmd(1) || bcnt(2)` CTAPHID header, so `[7..15]` is payload
    # `[0..8]` — only consistent when there is no status byte.
    #
    # DO NOT "fix" this to `init_reply[1:9]`. It is the obviously-right-looking
    # change and it would break against a working device.
    # ----------------------------------------------------------------------
    assert len(init_reply) == INIT_REPLY_LEN, (
        "CTAPHID INIT reply is %d bytes, expected the %d-byte "
        "nonce(8)||cid(4)||version(4)||capFlags(1) payload"
        % (len(init_reply), INIT_REPLY_LEN)
    )
    assert init_reply[:8] == INIT_NONCE, (
        "CTAPHID INIT did not echo the nonce at payload offset 0 (see the "
        "status-less-layout note above): %s" % init_reply.hex()
    )

    # The next two checks pin the bytes PicoForge actually consumes out of the
    # INIT reply — its new-channel read at report `[15..19]` and the capability
    # flag at payload `[16]`. Nothing else in the suite asserts them, and this
    # story's premise is that the token is *usable* by this consumer, so a
    # reply that echoed the nonce but handed back an unusable channel or
    # advertised no CBOR support would defeat the detection just as surely as a
    # wrong AAGUID.
    allocated_cid = init_reply[8:12]
    assert allocated_cid not in (INIT_CID_RESERVED, INIT_CID_BROADCAST), (
        "CTAPHID INIT allocated the %s channel, which accepts no follow-up "
        "command; PicoForge reads this as the channel it then sends GetInfo on"
        % ("reserved" if allocated_cid == INIT_CID_RESERVED else "broadcast")
    )
    assert init_reply[16] & INIT_CAP_FLAG_CBOR, (
        "CTAPHID INIT capabilityFlags 0x%02X does not advertise CTAP2 CBOR "
        "support (bit 0x%02X), so the GetInfo CBOR command this detection "
        "depends on would be refused" % (init_reply[16], INIT_CAP_FLAG_CBOR)
    )

    response = device.send_data(CTAPHID.CBOR, CTAP2_CMD_GET_INFO)
    assert response[0] == CTAP2_OK, (
        "GetInfo returned CTAP status 0x%02X, expected 0x00" % response[0]
    )
    info, _rest = cbor.decode_from(response[1:])
    assert isinstance(info, dict), "GetInfo did not return a CBOR map"
    return info


def test_device_serves_a_known_aaguid_and_it_is_the_right_one_for_this_build(device):
    """The AAGUID on the wire must be one of the two this project ships.

    **Two identities, one build, and which one is expected depends on the
    build.** The published default is fapico2's own AAGUID; the borrowed RS-Key
    value is what `FAPICO2_AAGUID_HEX` selects, and it is the only one
    PicoForge's three-entry profile table can classify today.

    So the assertion is two-part, and both halves matter: the bytes must be one
    of the two (an unknown AAGUID means the device is invisible to the app and
    nobody would learn why from a "classified as Unknown" message), *and* the
    one it serves must be the one the running build was configured to serve.
    A test hard-coded to either value would fail on the other build, which is
    not a defect — it is the other supported configuration.

    What this cannot assert, and no amount of editing here would fix: that a
    **default** build is classified as RS-Key. It is not, and is not meant to
    be, until PicoForge adds our AAGUID to `firmwares/mod.rs`. The test says so
    rather than skipping, because "the token is invisible to the app" is the
    single most important thing to know when reading a failure of the
    classification check below.
    """
    info = _detection_get_info(device)

    assert KEY_AAGUID in info, "getInfo is missing the AAGUID key (0x03)"
    raw_aaguid = info[KEY_AAGUID]
    # Checked before `bytes(...)`: a CBOR text string would make the coercion
    # below raise a bare `TypeError: string argument without an encoding` that
    # names neither the key nor the fault. An AAGUID is a byte string; a text
    # one is a protocol error worth reporting as such.
    assert isinstance(raw_aaguid, bytes), (
        "getInfo key 0x03 (AAGUID) must be a CBOR byte string, got %s"
        % type(raw_aaguid).__name__
    )
    assert len(raw_aaguid) == 16, "AAGUID must be 16 bytes, got %d" % len(raw_aaguid)

    served = raw_aaguid.hex().upper()
    assert served in (FAPICO2_AAGUID, RSKEY_AAGUID), (
        "AAGUID is %s, which is neither fapico2's published identity nor the "
        "borrowed RS-Key one. A device presenting a third AAGUID is "
        "unclassifiable by PicoForge, and nothing here can say why." % served
    )

    if served == FAPICO2_AAGUID:
        # The default build. Correct and expected — and unclassifiable by the
        # current app, which is the state the EPIC's upstream track exists to
        # end. Said out loud rather than asserted away.
        assert served != RSKEY_AAGUID, (
            "a default build must not carry the borrowed RS-Key identity: two "
            "tokens presenting the same AAGUID is the state US-101's flip and "
            "risk R-3 were about"
        )
        pytest.skip(
            "This build serves fapico2's own AAGUID (%s), which PicoForge's "
            "profile table does not carry yet — expected for a default build. "
            "Flash a FAPICO2_AAGUID_HEX=%s build to exercise the "
            "classification path itself."
            % (FAPICO2_AAGUID, RSKEY_AAGUID)
        )

    # The override build: this is the configuration that can be classified, and
    # the end-to-end proof the EPIC exists for — the exact string
    # `detect_by_aaguid()` compares against.
    assert served == RSKEY_AAGUID, (
        "this build presents fapico2's own AAGUID, so PicoForge's "
        "detect_by_aaguid() classifies it as Unknown and the OpenPGP applet "
        "is hidden. Build with FAPICO2_AAGUID_HEX=%s to exercise the "
        "classification path." % RSKEY_AAGUID
    )


def test_firmware_version_renders_as_the_branch_picoforge_takes(device):
    """getInfo ``0x0E`` must be packed *and* inside the two-component range.

    The consumer branches on magnitude, so this asserts the branch, not just
    non-zeroness: a value above 0xFFFF is non-zero but would be rendered as a
    three-component "major.minor.patch" by a client that was handed a value
    fapico2 deliberately packed as two components.
    """
    info = _detection_get_info(device)

    assert KEY_FIRMWARE_VERSION in info, (
        "getInfo is missing the firmwareVersion key (0x0E)"
    )
    raw = info[KEY_FIRMWARE_VERSION]
    # `type(...) is int`, not `isinstance(..., int)`: CBOR `true` decodes to a
    # Python bool, which *is* an int subclass, so isinstance would silently
    # accept True here (1, which would then even pass the non-zero check).
    assert type(raw) is int, (
        "firmwareVersion must be a CBOR unsigned integer, got %s"
        % type(raw).__name__
    )

    assert raw != 0, (
        "firmwareVersion is 0, which renders as \"0.0\" and drives every "
        "version-gated branch in the client onto the wrong answer (US-102)"
    )
    assert raw <= FIRMWARE_VERSION_TWO_COMPONENT_MAX, (
        "firmwareVersion 0x%X is above 0xFFFF, so PicoForge's "
        "format_firmware_version() takes the `major.minor.patch` branch on a "
        "value fapico2 packed as (major << 8) | minor" % raw
    )
    expected = _workspace_firmware_version()
    assert raw == expected, (
        "firmwareVersion is %d (0x%X), but packing the workspace manifest "
        "version as (major << 8) | minor gives %d (0x%X)" % (raw, raw, expected, expected)
    )
    # And the branch the consumer will take renders a real version, not "0.0".
    assert "%d.%d" % ((raw >> 8) & 0xFF, raw & 0xFF) != "0.0"
