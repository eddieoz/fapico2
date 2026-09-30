"""US-123 (EPIC `PICOForge-COMPAT`): the client-side outcome of getInfo ``0x0E``.

US-102 packed ``firmwareVersion`` as ``(major << 8) | minor``. US-123 is the
*consumer-side* half of that story: it ports the PicoForge client logic that
turns those raw bytes into a displayed version and into capability decisions,
and asserts on the result of running that logic against this device.

## Not PicoForge itself — the single most important caveat

**No PicoForge code runs.** The client logic under examination is Rust
(`picoforge/src/hal/...`) that is never invoked here; what runs is a Python
**transcription** of it, written by hand into this file. If
`format_firmware_version`, the management fallback, or either capability gate
changes upstream, **every test in this module stays green** while the real
client behaves differently. This file is a guard on *our* reading of the
client, not on the client.

The same applies to the firmware-profile table: it is mirrored here as
literals (`RSKEY_AAGUID`, the profile names, the gate values), so a change to
PicoForge's table shows up here only as long as somebody remembers to mirror
it. This is the same caveat `test_090_picoforge_detect.py` states for the
detection table, and this module is worse off, because here the *behaviour* is
transcribed too, not just a constant.

## What is genuinely new here, and what is not

The wire-level guard lives in
`test_090_picoforge_detect.py::test_firmware_version_renders_as_the_branch_picoforge_takes`
and in `apps/fido/tests/getinfo.rs::firmware_version_nonzero`: raw non-zero,
within the two-component range, equal to the packed workspace manifest
version. This module does not restate that.

There is deliberate, bounded overlap, and it is worth being exact about it:

* ``test_090:295`` evaluates ``"%d.%d" % (...) != "0.0"`` on the raw value. The
  two-component branch in `test_rendered_version_reaches_the_client_unmasked`
  below evaluates the same expression through the ported function. Overlap,
  but there the count of components is the load-bearing claim.
* ``test_090:250`` asserts the AAGUID equals `RSKEY_AAGUID`. Here the AAGUID is
  the **input** to profile resolution, not a standalone assertion; the claim
  is what the client *does* with it, not its value.
* The AAGUID is **not** re-compared against the manifest packing here — that
  binding is `test_090`'s (`:289`), and restating it would be the test
  asserting its own arithmetic.

What no other test covers: `test_rendered_version_takes_the_management_fallback`
evaluates the `mod.rs:694-701` fallback **decision** and asserts the branch is
not taken. `test_090` establishes the raw integer is non-zero; only the
rendered string is what the client branches on.

## [EMU]

Same caveat as `test_090`: this runs against the emulated CTAPHID transport, so
it is a regression guard on the transcription above, not a hardware
qualification result. The `device` fixture supplies a real `GetInfo` over real
CTAPHID framing; everything downstream of the decoded CBOR map is the Python
port.
"""

import pytest

from test_090_picoforge_detect import (
    KEY_AAGUID,
    KEY_FIRMWARE_VERSION,
    FAPICO2_AAGUID,
    RSKEY_AAGUID,
    _detection_get_info,
)

# `picoforge/src/hal/fido/mod.rs:133` — the two-branch cut-over. Strictly
# greater takes the three-component branch; 0xFFFF itself is two-component.
FORMAT_TWO_COMPONENT_MAX = 0xFFFF

# The sentinel `read_device_details` (`picoforge/src/hal/fido/mod.rs:694`)
# compares the rendered string against, and the literal it falls back to.
FALLBACK_SENTINEL = "0.0"
FALLBACK_UNKNOWN = "Unknown"

# Profile names, as `picoforge/src/hal/types.rs:153-161` (`FirmwareType`) spells
# them.
PROFILE_RSKEY = "RSKey"
PROFILE_PICOFIDO = "PicoFido"
PROFILE_UNKNOWN = "Unknown"

# The RS-Key gate values (`picoforge/src/hal/firmwares/rskey.rs:38-50`). Both
# are literals on the impl — the struct holds a `version` field that neither
# reads. They are referenced only as *expectations* for the resolved profile,
# never asserted against themselves.
RSKEY_LEGACY_HARDWARE_CONFIG = False
RSKEY_FIDO_CONFIG_WRITE = True


def format_firmware_version(raw):
    """Port of ``picoforge/src/hal/fido/mod.rs:133-144``.

    ``raw`` is the CBOR integer from getInfo key ``0x0E``; picoforge types it
    as ``i128`` and this test passes Python's unbounded int, which is
    equivalent for every value reachable here.
    """
    if raw > FORMAT_TWO_COMPONENT_MAX:
        return "%d.%d.%d" % ((raw >> 16) & 0xFF, (raw >> 8) & 0xFF, raw & 0xFF)
    return "%d.%d" % ((raw >> 8) & 0xFF, raw & 0xFF)


def resolve_firmware_version(fido_version, management_version):
    """Port of the management fallback at ``picoforge/src/hal/fido/mod.rs:694-701``.

    Mirrors the expression verbatim: the CTAP version wins unless it renders as
    the ``"0.0"`` sentinel, in which case the management applet's string is
    used, and ``"Unknown"`` if there is none.
    """
    if fido_version != FALLBACK_SENTINEL:
        return fido_version
    if management_version is not None:
        return management_version
    return FALLBACK_UNKNOWN


def detect_profile(aaguid_hex):
    """Port of the AAGUID table, ``picoforge/src/hal/fido/mod.rs:648-654``.

    ``AnyFirmware::detect_by_aaguid`` (``picoforge/src/hal/firmwares/mod.rs:73-83``)
    is the same three-entry lookup; the copy inside ``read_device_details`` is
    the one on this code path.
    """
    if aaguid_hex == RSKEY_AAGUID:
        return PROFILE_RSKEY
    return PROFILE_UNKNOWN


def resolve_gates(profile, major, minor):
    """The two gates the EPIC's US-123 rationale names, resolved by profile.

    Ports ``FirmwareTrait::supports_legacy_fido_hardware_config`` /
    ``supports_fido_config_write`` for the profiles this device can resolve to.
    ``has_legacy_vendor`` is false: the probe
    (``picoforge/src/hal/fido/mod.rs:870-882``) is short-circuited by the
    firmware type at ``:655-656``, and only the PicoFido arm consults it.

    For ``RSKey`` (``picoforge/src/hal/firmwares/rskey.rs:38-50``) ``major`` and
    ``minor`` are accepted and ignored — that is the point of the third test.
    For ``PicoFido`` (``picoforge/src/hal/firmwares/picofido.rs:50-58``) they
    are the whole decision.
    """
    if profile == PROFILE_RSKEY:
        return RSKEY_LEGACY_HARDWARE_CONFIG, RSKEY_FIDO_CONFIG_WRITE
    if profile == PROFILE_PICOFIDO:
        legacy = major < 7 or (major == 7 and minor <= 2)
        return legacy, major >= 7
    # Unknown / LK-ONE fall back to a PicoFidoFirmware in `new_with_legacy`.
    legacy = major < 7 or (major == 7 and minor <= 2)
    return legacy, major >= 7


def _rendered_version(device):
    """The client-side string for this device, plus the raw value behind it."""
    info = _detection_get_info(device)
    assert KEY_FIRMWARE_VERSION in info, (
        "getInfo is missing the firmwareVersion key (0x0E)"
    )
    raw = info[KEY_FIRMWARE_VERSION]
    # `type(...) is int`: CBOR `true` decodes to a bool, which is an int
    # subclass. Same guard as test_090.
    assert type(raw) is int, (
        "firmwareVersion must be a CBOR unsigned integer, got %s"
        % type(raw).__name__
    )
    return raw, format_firmware_version(raw)


def test_rendered_version_reaches_the_client_unmasked(device):
    """The rendered string is a real two-component version, not ``"0.0"``.

    The client never sees the packed integer — it sees a string. The count of
    components is the load-bearing claim: fapico2 packs ``(major << 8) | minor``
    for the ``else`` branch of the ported function, and a three-component
    render means the ``raw > 0xFFFF`` branch was taken on a two-component
    encoding. The sentinel is asserted because it is the story's headline and
    because it is what the next test's fallback decision keys on.

    No claim is made here about the value relative to the workspace manifest:
    that binding is ``test_090:289``, and re-deriving it here would be this
    test comparing its own arithmetic.
    """
    _raw, rendered = _rendered_version(device)

    components = rendered.split(".")
    assert len(components) == 2, (
        "format_firmware_version rendered %r with %d components; fapico2 packs "
        "(major << 8) | minor, so the client must take the two-component branch"
        % (rendered, len(components))
    )
    assert rendered != FALLBACK_SENTINEL, (
        "format_firmware_version rendered the %r sentinel, so "
        "read_device_details discards the CTAP version entirely (US-102/US-123)"
        % FALLBACK_SENTINEL
    )


def test_rendered_version_takes_the_management_fallback(device):
    """The ``"0.0"`` fallback branch is unreachable for this device.

    This is the part US-123 adds. ``test_090`` establishes that the *raw
    integer* is non-zero, but only the rendered string is what
    ``read_device_details`` branches on. A packing that renders ``"0.0"`` while
    staying non-zero (e.g. a value whose two byte components both vanish)
    would slip past the wire-level guard; this asserts the decision point
    itself.

    Both management outcomes are evaluated, because the branch is only
    observable when it is taken: with no management applet the display becomes
    the literal ``"Unknown"``, and with one the CTAP version is displaced.
    """
    _raw, rendered = _rendered_version(device)

    from_ctap = resolve_firmware_version(rendered, None)
    assert from_ctap != FALLBACK_UNKNOWN, (
        "the management fallback was taken: no management applet answered and "
        "the CTAP version rendered as %r, so read_device_details would display "
        "%r (US-123)" % (rendered, FALLBACK_UNKNOWN)
    )
    from_management = resolve_firmware_version(rendered, "9.9")
    assert from_management == rendered, (
        "the management applet's version (%r) displaced the CTAP version (%r); "
        "that only happens when the CTAP string equals %r"
        % (from_management, rendered, FALLBACK_SENTINEL)
    )
    assert from_ctap == rendered and from_management == rendered


def test_capability_gates_do_not_depend_on_our_version(device):
    """Our profile's gate answers are the same at any version.

    A negative claim, and the only one in this module with a real referent:
    the profile is selected from the AAGUID, and for the profile this device
    resolves to, the version is not an input to either gate. So the answers
    are the same at the version the device actually reports and at versions
    on both sides of the pico-fido 7.x boundary — where the *other* profile
    would answer differently, and differently from itself.

    This is device-anchored in two places, neither of them the gate values:
    the AAGUID read from the device is the input to profile resolution, and the
    device's own reported version is one of the inputs to the invariance check.
    A firmware change that made the gates version-dependent, or an AAGUID that
    resolved to a different profile, both fail here.

    It does **not** assert how the pico-fido profile would answer for our
    version: that answer changes with every workspace version bump, and a
    version-fragile assertion with no referent is worse than none.
    """
    info = _detection_get_info(device)
    raw_aaguid = info.get(KEY_AAGUID)
    assert isinstance(raw_aaguid, bytes), (
        "getInfo key 0x03 (AAGUID) must be a CBOR byte string, got %s"
        % type(raw_aaguid).__name__
    )
    served = raw_aaguid.hex().upper()
    # The AAGUID must be one this project ships. A third value is a real
    # fault — an unclassifiable device with nothing to point at — and it is
    # worth distinguishing from the *expected* unclassifiable case below.
    assert served in (FAPICO2_AAGUID, RSKEY_AAGUID), (
        "AAGUID %s is neither fapico2's published identity nor the borrowed "
        "RS-Key one" % served
    )

    profile = detect_profile(served)
    if profile == PROFILE_UNKNOWN:
        # Everything this test says about the *version* still holds; what does
        # not exist on a default build is a profile to hang the gate
        # invariance on. Said out loud rather than hidden behind a bare skip,
        # because "the token is invisible to the app" is the most important
        # thing to know when reading this file's output.
        pytest.skip(
            "AAGUID %s is fapico2's own, which PicoForge's profile table does "
            "not carry yet, so the gate-invariance claim has no profile to "
            "attach to. Expected for a default build; flash a "
            "FAPICO2_AAGUID_HEX=%s image to exercise it."
            % (served, RSKEY_AAGUID)
        )

    assert profile == PROFILE_RSKEY, (
        "AAGUID %s resolved to the %s profile, not RS-Key; the gate "
        "invariance asserted below is RS-Key's, and a different profile may "
        "gate on version" % (served, profile)
    )

    _raw, rendered = _rendered_version(device)

    components = rendered.split(".")
    assert len(components) == 2, (
        "format_firmware_version rendered %r with %d components; fapico2 packs "
        "(major << 8) | minor, so the client must take the two-component branch"
        % (rendered, len(components))
    )
    assert rendered != FALLBACK_SENTINEL, (
        "format_firmware_version rendered the %r sentinel, so "
        "read_device_details discards the CTAP version entirely (US-102/US-123)"
        % FALLBACK_SENTINEL
    )
