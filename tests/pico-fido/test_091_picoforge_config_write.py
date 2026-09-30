"""US-117 (EPIC `PICOForge-COMPAT`): `DEV_CONF` and `LED` over `0x41` `CONFIG_WRITE`.

Two RS-Key `CONFIG_WRITE` targets that did not exist before this story, driven
end-to-end over the emulated CTAP-HID transport:

* **`DEV_CONF` (`0x00`)** — the USB enabled-interface mask, as management TLV
  `03 02 <enabled BE u16>`` (`write_rskey_dev_config`,
  `picoforge/src/hal/fido/mod.rs:2086-2091`; the tag constant
  `FIDO_MGMT_TAG_USB_ENABLED` is at `:2071`).
* **`LED` (`0x02`)** — the 17-byte status block
  `[steady(1), (effect, color, brightness, speed) × 4]`
  (`RSKEY_LED_CONF_LEN`, `picoforge/src/hal/fido/mod.rs:2001`).

## What this test actually proves — read before citing it as hardware evidence

This is an **[EMU]** test. It runs against the `fapico2-emulation` host binary
(`--target x86_64-unknown-linux-gnu`, `feature = "emulation"`), reached through
`tests/harness/hid_emul.py`, which splices a plain TCP socket into
python-fido2's HID backend.

**Covered:** that the four-byte `DEV_CONF` TLV and the 17-byte LED block
survive the real wire path — CBOR framing, the `0x41` vendor opcode, the
`verify_mac` HMAC, and a commit through the device keystore's `grow_checked` —
and that `CONFIG_READ` at `0x02` hands back the block the `CONFIG_WRITE`
stored.

**NOT covered here, and this is the one that matters for reading the suite:**
**the field-tier gates are not exercised by this file.** Every test below
supplies a valid `0x20` token, and the emulation path auto-acks presence, so
both gates are on their *accepting* side for the whole run. A `DEV_CONF` write
downgraded from the identity tier to the presence tier — the single security
decision this story makes — would leave **all five of these tests green**,
because a presence grant is all the downgraded arm would then need.

The gate is covered by `dev_conf_write_is_the_identity_tier_not_presence` in
`apps/fido/tests/vendor41.rs`, whose three legs (no token, token-without-press,
press-without-token) are what make the tier a test rather than a claim. That
file, not this one, is where the tier classification is proven; this file is
where the two record formats are proven. Do not read a green run here as
evidence about either gate's strength.

**NOT covered — do not read a green run as any of the following:**

* **Not hardware.** No RP2350, no USB, and no CCID path. The gate tiers and the
  commit are shared between the device and emulation paths (both are
  `FidoApp`s), so this says something about them; it is not a hardware
  qualification result and it does not exercise the HID task's `UpRequired`
  retry loop, which is where a presence-tier write actually waits for a press.
  The `0x3B` leg of the presence tier is therefore *not* reachable from here —
  the emulation path auto-acks presence (`PresenceGate::default` resolves
  through `default_user_present`), so a "refused without a press" assertion
  would be asserting about a probe this transport does not have.
* **Not the interface mask taking effect.** Both records are **stored, not
  applied**, on the same grounds as the VID/PID US-113 added: the USB
  descriptors are a compile-time `CONFIG_DESC` and nothing reads
  `PhyConfig` to drive hardware. A passing `DEV_CONF` write means the mask was
  accepted, gated, and made durable — not that any USB interface appeared or
  disappeared.
* **Not the zero-mask denial of service.** A mask of `0` is refused before the
  gate precisely because accepting it would remove the token from every host on
  the bus. This test asserts the *refusal*; it cannot and does not observe the
  re-enumeration, because refusing is the point.
* **Not `DEV_CONF` being readable.** It is not, by design — see
  `dev_conf_read_is_refused`. The client reads enabled-apps over the `0xC2`
  Management path instead (`picoforge/src/hal/fido/mod.rs:615-623`).

## The read-modify-write, and where it actually lives

The EPIC text for this story says the *device* must read the old LED block
first, "or it will zero effect and speed". The device does not, and cannot: the
read-modify-write is **client-side**, in `write_rskey_led_config`
(`picoforge/src/hal/fido/mod.rs:2036-2063`), which reads the current block,
copies it, and overwrites only `block[0]`, `block[2 + 4i]` and `block[3 + 4i]`.

So the risk the EPIC names is real, but it lives on the **read**:

```python
block = [0] * 17
if current := read_led_block():      # <- a failure here is the bug
    block[:17] = current
block[0] = steady
for i, (color, brightness) in enumerate(statuses):
    block[2 + 4 * i] = color & 0x07
    block[3 + 4 * i] = brightness
```

A device that stored the block but **refused to read it back** would take that
`if` as false, leave `block` all-zero, and wipe every WS2812 effect and speed —
the exact failure, reached by the other road. That is why US-117 also makes
`0x02` readable, and why `led_read_modify_write_preserves_effect_and_speed`
below is a test about the *read* rather than about the write.

## The 17-byte layout, cross-checked against something independent

`LED_BLOCK_EXAMPLE` is transcribed from the **client's own** unit test,
`parses_current_17_byte_block` (`picoforge/src/hal/common/led.rs:49-60`), which
uses it to pin `parse_led_block`. It is not generated from this firmware's
encoder: a hand-written expectation is only useful if it is checked against
something independent, and an expectation produced by the code under test
proves only that the code agrees with itself. The same bytes are asserted
against the offsets this firmware and the client must agree on
(`EFFECT_AT = 1 + 4i`, `COLOR_AT = 2 + 4i`, `BRIGHTNESS_AT = 3 + 4i`,
`SPEED_AT = 4 + 4i`).
"""

import hashlib
import hmac

from fido2 import cbor
from fido2.ctap2.pin import ClientPin
from fido2.hid import CTAPHID

PIN = "1234"

# CTAP2 vendor opcode that carries the RS-Key sub-commands
# (`RSKEY_CTAPHID_VENDOR_CMD`, `picoforge/src/hal/fido/constants.rs:717`).
VENDOR_41 = 0x41
# `RSKEY_CONFIG_WRITE` / `RSKEY_CONFIG_READ`
# (`picoforge/src/hal/fido/constants.rs:730` / `:726`).
CONFIG_WRITE = 0x0C
CONFIG_READ = 0x0D

# `RSKEY_CFG_TARGET_*` (`picoforge/src/hal/fido/constants.rs:771-775`).
TARGET_DEV_CONF = 0x00
TARGET_PHY = 0x01
TARGET_LED = 0x02

# `FIDO_MGMT_TAG_USB_ENABLED` (`picoforge/src/hal/fido/mod.rs:2071`) — a
# *management* tag, deliberately not one of the twelve PHY tags.
DEV_CONF_TAG_USB_ENABLED = 0x03

# `RSKEY_LED_CONF_LEN` (`picoforge/src/hal/fido/mod.rs:2001`).
LED_BLOCK_LEN = 17

# The block layout, from `write_rskey_led_config`'s index arithmetic
# (`picoforge/src/hal/fido/mod.rs:2051-2056`) cross-checked against
# `parse_led_block`'s `base = 1 + stride * i + color_off` with `stride == 4` and
# `color_off == 1` (`picoforge/src/hal/common/led.rs:33-38`).
STEADY_AT = 0
EFFECT_AT = lambda i: 1 + 4 * i  # noqa: E731
COLOR_AT = lambda i: 2 + 4 * i  # noqa: E731
BRIGHTNESS_AT = lambda i: 3 + 4 * i  # noqa: E731
SPEED_AT = lambda i: 4 + 4 * i  # noqa: E731

# The client's own 17-byte example, from `parses_current_17_byte_block`
# (`picoforge/src/hal/common/led.rs:51-57`). Chosen because every effect,
# colour, brightness and speed differs from every other, so a transposed
# offset cannot produce these bytes by accident.
LED_BLOCK_EXAMPLE = bytes(
    [
        0x01,  # steady
        0x00, 0x02, 0x40, 0x00,  # idle:  effect 0, green, br 0x40, speed 0
        0x01, 0x03, 0x20, 0x05,  # proc:  effect 1, blue,  br 0x20, speed 5
        0x02, 0x04, 0x10, 0x0F,  # touch: effect 2, yellow, br 0x10, speed 15
        0x00, 0x01, 0x08, 0x00,  # boot:  effect 0, red,   br 0x08, speed 0
    ]
)

# A mask the client would plausibly send: a few interface bits on.
DEV_CONF_MASK = 0x000B

# CTAP2 status byte, §11.2.4.
CTAP2_OK = 0x00


# ---------------------------------------------------------------------------
# Wire helpers — PicoForge's own construction, transcribed.
# ---------------------------------------------------------------------------


def _config_params(target, blob):
    """`subCommandParams` for `CONFIG_WRITE`: `{1: target, 2: h'blob'}`.

    The inverse of `rs_key_config_write` (`picoforge/src/hal/fido/ops.rs:1519-1524`).
    """
    return cbor.encode({1: target, 2: blob})


def _read_params(target):
    """`subCommandParams` for `CONFIG_READ`: `{1: target}`.

    `rs_key_config_read` builds `{1: target}` and sends **no key 3 and no
    key 4** (`picoforge/src/hal/fido/ops.rs:1461-1479`), so this request is
    unauthenticated by design.
    """
    return cbor.encode({1: target})


def _vendor_mac(token, sub, params):
    """`HMAC-SHA256(token, 0xFF*32 || 0x41 || sub || cbor(params))[0..16]`.

    Exactly what `rs_key_config_write` builds
    (`picoforge/src/hal/fido/ops.rs:1526-1534`). The four pieces are all
    load-bearing and each is a way for the two sides to disagree:

    * `0xFF * 32` — the CTAP2 null-authenticator-data prefix, which is what
      makes this message distinguishable from a `pinUvAuthParam` over an
      authenticator command (`0x00…`);
    * `0x41` — the domain separator, so a MAC harvested from the sibling
      vendor-vault `0x41` cannot be replayed here;
    * `sub` — so one sub-command's authorisation is not spendable on another;
    * `cbor(params)` — so the authorisation is bound to *what is being asked
      for*, which is the whole point of the construction.
    """
    message = b"\xff" * 32 + bytes([VENDOR_41, sub]) + params
    return hmac.new(token, message, hashlib.sha256).digest()[:16]


def _bstr(data):
    """A CBOR byte string with a definite length.

    Only the one- and two-byte length forms are needed here: a params value is
    at most a few dozen bytes and the MAC is 16. There is no indefinite form,
    which is why the wire format has no way to express a blob over 255 bytes at
    all.
    """
    assert len(data) < 256, "a test blob this long would need a length form this does not build"
    return b"\x58" + bytes([len(data)]) + data


def _config_write(device, token, target, blob):
    """Send a `CONFIG_WRITE` and return `(status, body)`.

    # Why the CBOR is assembled by hand here

    The outer map has to splice `params` in as a **map**, not as a byte string,
    and the MAC has to be taken over exactly the bytes that end up on the wire.
    Building it with `cbor.encode` and a nested dict would make the second
    condition depend on the encoder re-serialising the map identically to the
    standalone `cbor.encode({1: target, 2: blob})` the MAC was computed over —
    which is true today and is not a property this test should depend on, since
    the device verifies the *wire* bytes rather than a re-encoding
    (`verify_mac` captures the raw span, deliberately, so no canonical-CBOR
    drift is possible).

    So: encode the params once, MAC those bytes, then splice them in verbatim.

    `body` is the CBOR half, which is only meaningful when `status == 0` — the
    client applies the same rule, parsing the CBOR half only when the status
    byte is zero (`HidTransport::read_cbor_response`).
    """
    params = _config_params(target, blob)
    mac = _vendor_mac(token, CONFIG_WRITE, params)
    payload = bytes([VENDOR_41]) + b"".join(
        [
            b"\xa4",  # map(4)
            b"\x01",
            bytes([CONFIG_WRITE]),  # key 1 = subCommand
            b"\x02",
            params,  # key 2 = subCommandParams, spliced verbatim
            b"\x03",
            b"\x01",  # key 3 = pinUvAuthProtocol 1
            b"\x04",
            _bstr(mac),  # key 4 = pinUvAuthParam
        ]
    )
    reply = device.send_data(CTAPHID.CBOR, payload)
    return reply[0], reply[1:]


def _config_read(device, target):
    """Send a `CONFIG_READ` (unauthenticated) and return `(status, body)`."""
    payload = bytes([VENDOR_41]) + b"\xa2" + b"\x01" + bytes([CONFIG_READ]) + b"\x02" + _read_params(target)
    reply = device.send_data(CTAPHID.CBOR, payload)
    return reply[0], reply[1:]


def _read_led_block(device):
    """The client's read side: `CONFIG_READ` at `0x02`, unwrapping key 1."""
    status, body = _config_read(device, TARGET_LED)
    assert status == CTAP2_OK, (
        "CONFIG_READ at target 0x02 answered 0x%02X. The client's "
        "read-modify-write is guarded on `current.len() >= RSKEY_LED_CONF_LEN` "
        "(picoforge/src/hal/fido/mod.rs:2045-2047), so a non-OK status takes "
        "the all-zero fall-through and the next colour write silently wipes "
        "every effect and speed" % status
    )
    decoded, _rest = cbor.decode_from(body)
    assert isinstance(decoded, dict), "CONFIG_READ did not return a CBOR map"
    assert 1 in decoded, (
        "CONFIG_READ response is missing key 1, the record itself; the client "
        "unwraps it unconditionally (picoforge/src/hal/fido/ops.rs:1480-1487)"
    )
    block = decoded[1]
    assert isinstance(block, bytes), (
        "key 1 must be a CBOR byte string, got %s" % type(block).__name__
    )
    return block


def _acfg_token(device):
    """A pinUvAuthToken carrying `AUTHENTICATOR_CONFIG` (`0x20`).

    That is the permission the client mints for every `CONFIG_WRITE` call site
    (`ops.rs:1576-1580` and the `mod.rs` callers at `:1168`, `:1310`, `:1432`,
    `:1464`, `:2057`, `:2093`).
    """
    ctap = device.client()._backend.ctap2
    client_pin = ClientPin(ctap)
    client_pin.set_pin(PIN)
    return client_pin.get_pin_token(
        PIN,
        permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG,
    )


def _dev_conf_blob(mask):
    """The `DEV_CONF` record: `03 02 <mask big-endian u16>`.

    Transcribed from the client's own array literal
    (`picoforge/src/hal/fido/mod.rs:2086-2091`), which pushes
    `(enabled_mask >> 8) as u8` **before** `enabled_mask & 0xFF`. The width is
    fixed at two and the order is big-endian, so `0x000B` is `03 02 00 0B` and
    not `03 02 0B 00`.
    """
    return bytes([DEV_CONF_TAG_USB_ENABLED, 0x02, (mask >> 8) & 0xFF, mask & 0xFF])


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------


def test_dev_conf_and_led_roundtrip(device):
    """`DEV_CONF` and `LED` are written over `0x41`, gated, and made durable.

    The story's named test. Four things have to hold for the PicoForge Config
    screen to work, and each is a place the story could have stopped short:

    1. a `0x20` token authorises both writes and both commit;
    2. the `DEV_CONF` mask survives as a **big-endian** number;
    3. the LED block survives **byte for byte**;
    4. `CONFIG_READ` at `0x02` hands the block back, so the client's
       read-modify-write has something to copy.

    Leg (4) is the one worth reading the EPIC for — see the module docstring.
    Without it the writes would still answer `0x00`, and the *next* colour
    change would still wipe every effect and speed.
    """
    device.reset()
    token = _acfg_token(device)

    # --- DEV_CONF: the USB enabled-interface mask ---
    dev_conf = _dev_conf_blob(DEV_CONF_MASK)
    assert dev_conf == bytes([0x03, 0x02, 0x00, 0x0B]), (
        "the DEV_CONF TLV is [tag 0x03, len 2, high byte, low byte] — "
        "`write_rskey_dev_config` pushes (mask >> 8) before (mask & 0xFF) "
        "(picoforge/src/hal/fido/mod.rs:2086-2091). Getting this backwards "
        "would set a mask of 0x0B00 = 2816 and enumerate 2816 interfaces"
    )

    status, _ = _config_write(device, token, TARGET_DEV_CONF, dev_conf)
    assert status == CTAP2_OK, (
        "a DEV_CONF write carrying a 0x20 token must be accepted: DEV_CONF is "
        "the identity tier, and a pinUvAuthToken with AUTHENTICATOR_CONFIG is "
        "the authority for it. Answered 0x%02X" % status
    )

    # --- LED: the 17-byte status block ---
    status, _ = _config_write(device, token, TARGET_LED, LED_BLOCK_EXAMPLE)
    assert status == CTAP2_OK, (
        "an LED block must be accepted: it is a cosmetic overlay, and a touch "
        "is its authority. Answered 0x%02X" % status
    )

    # --- and both are readable back, over the same wire ---
    block = _read_led_block(device)
    assert len(block) == LED_BLOCK_LEN, (
        "the LED block read back is %d bytes, not %d (`RSKEY_LED_CONF_LEN`, "
        "picoforge/src/hal/fido/mod.rs:2001)" % (len(block), LED_BLOCK_LEN)
    )
    assert block == LED_BLOCK_EXAMPLE, (
        "the block did not survive the round trip. Stored %s, read back %s. "
        "Both are the client's own example block, so a difference here is a "
        "mangling of the block in one direction or the other, not a difference "
        "of opinion about the layout"
        % (LED_BLOCK_EXAMPLE.hex(), block.hex())
    )

    # The offsets, asserted against the client's index arithmetic rather than
    # against a round trip, so a symmetric encoder/decoder pair that agreed
    # with each other and disagreed with the client would still fail here.
    assert block[STEADY_AT] == 0x01, "index 0 is `steady`"
    for i in range(4):
        assert block[COLOR_AT(i)] in (0x01, 0x02, 0x03, 0x04), (
            "index %d is `color` for record %d; the client writes it masked to "
            "0x07" % (COLOR_AT(i), i)
        )
    assert [block[SPEED_AT(i)] for i in range(4)] == [0x00, 0x05, 0x0F, 0x00], (
        "index 4+4i is `speed`, and the client's example block has "
        "0x00/0x05/0x0F/0x00 there. A firmware that shifted the stride by one "
        "would read the effect bytes as speeds"
    )


def test_led_read_modify_write_preserves_effect_and_speed(device):
    """The client's read-modify-write, run the way the client runs it.

    This is the failure the EPIC predicted, checked end-to-end over the wire.
    A device that stored the LED block but refused to serve it at `0x02` would
    make the client's `if` fall through to an all-zero block, and the colour
    and brightness written below would land on a block whose effect and speed
    bytes are all zero — silently discarding whatever the operator had set.

    The order is the client's (`picoforge/src/hal/fido/mod.rs:2043-2057`):
    read, copy, overwrite `block[0]` / `block[2 + 4i]` / `block[3 + 4i]`, write
    the whole 17 bytes back. Nothing else is assumed about the device beyond
    that.
    """
    device.reset()
    token = _acfg_token(device)

    # A starting block with non-zero effect and speed everywhere, so
    # "preserved" and "zeroed" are distinguishable at all sixteen bytes.
    start = bytearray(LED_BLOCK_LEN)
    start[STEADY_AT] = 0x01
    for i in range(4):
        start[EFFECT_AT(i)] = 0x07 - i
        start[COLOR_AT(i)] = i + 1
        start[BRIGHTNESS_AT(i)] = 0x10 + i
        start[SPEED_AT(i)] = 0x11 + i

    status, _ = _config_write(device, token, TARGET_LED, bytes(start))
    assert status == CTAP2_OK, "precondition: the starting block is accepted"
    assert _read_led_block(device) == bytes(start), (
        "precondition: the starting block reads back unchanged"
    )

    # --- the client's algorithm, verbatim in effect ---
    block = bytearray(_read_led_block(device))
    block[STEADY_AT] = 0x00  # steady off
    for i in range(4):
        block[COLOR_AT(i)] = 5 & 0x07  # colour, masked exactly as the client does
        block[BRIGHTNESS_AT(i)] = 0x40
    # --- effect (1+4i) and speed (4+4i) are deliberately left untouched ---

    status, _ = _config_write(device, token, TARGET_LED, bytes(block))
    assert status == CTAP2_OK, "the read-modify-write is accepted"

    final = _read_led_block(device)
    assert final[STEADY_AT] == 0x00, "steady is one of the three fields written"
    for i in range(4):
        assert final[COLOR_AT(i)] == 5, (
            "colour at %d is a field the client writes" % COLOR_AT(i)
        )
        assert final[BRIGHTNESS_AT(i)] == 0x40, (
            "brightness at %d is a field the client writes" % BRIGHTNESS_AT(i)
        )
        assert final[EFFECT_AT(i)] == start[EFFECT_AT(i)], (
            "effect at index %d was NOT written by the client and must survive. "
            "It is 0x%02X, was 0x%02X. This is the silent-wipe the EPIC warns "
            "about: it happens when the CONFIG_READ at 0x02 fails or answers "
            "short, because the client then copies an all-zero block"
            % (EFFECT_AT(i), final[EFFECT_AT(i)], start[EFFECT_AT(i)])
        )
        assert final[SPEED_AT(i)] == start[SPEED_AT(i)], (
            "speed at index %d was NOT written by the client and must survive. "
            "It is 0x%02X, was 0x%02X" % (SPEED_AT(i), final[SPEED_AT(i)], start[SPEED_AT(i)])
        )


def test_dev_conf_rejects_the_zero_mask(device):
    """`03 02 00 00` is refused even from a caller holding a `0x20` token.

    A zero USB enabled-interface mask makes the device re-enumerate with no
    interfaces: gone from every attached host until BOOTSEL recovery. That is a
    denial of service against the whole bus, it is reachable with the weakest
    authority this tier admits, and it has no legitimate use — there is no
    configuration in which "this authenticator presents nothing" is what an
    operator meant.

    So it is refused **before** the gate rather than inside the identity
    branch, which is stronger than "gated behind the token" and is why the leg
    below presents a fully valid token: a gate in front of this rule would let
    anyone who can obtain a token take the device off the bus.

    The positive leg matters too — without it this test would pass if the
    device refused every `DEV_CONF` write.
    """
    device.reset()
    token = _acfg_token(device)

    status, _ = _config_write(device, token, TARGET_DEV_CONF, _dev_conf_blob(0x0000))
    assert status != CTAP2_OK, (
        "a zero enabled-USB-interface mask was accepted. The device would "
        "re-enumerate with no USB interfaces and vanish from every attached "
        "host until BOOTSEL recovery"
    )

    status, _ = _config_write(device, token, TARGET_DEV_CONF, _dev_conf_blob(0x0001))
    assert status == CTAP2_OK, (
        "the smallest non-zero mask must still be accepted by the same token, "
        "or this test is passing because every DEV_CONF write is refused rather "
        "than because the zero mask is. Answered 0x%02X" % status
    )


def test_dev_conf_read_is_refused(device):
    """`CONFIG_READ` at `0x00` stays refused, and that is the protocol's answer.

    Not this firmware's policy — the client's: *"Enabled-apps info is NOT
    readable over the `0x41` CONFIG_READ path — the firmware exposes only PHY/LED
    there and rejects DEV_CONF"* (`picoforge/src/hal/fido/mod.rs:615-618`). The
    client routes around it, reading enabled-apps over the `0xC2` Management
    path (`:615-622`).

    So this is a *write-only* target, and the honest reason is the record's
    content: the interface mask is the one configuration blob that changes what
    the token can do on the bus, and `CONFIG_READ` is the one sub-command the
    client sends with no token and no MAC at all
    (`picoforge/src/hal/fido/ops.rs:1461-1479`), as its feature probe for
    whether the firmware supports `0x41`. An unauthenticated read of the mask
    is exactly the thing the write-side tiering exists to prevent, so it stays
    out of reach.
    """
    device.reset()
    status, body = _config_read(device, TARGET_DEV_CONF)
    assert status != CTAP2_OK, (
        "DEV_CONF answered 0x00 to an unauthenticated CONFIG_READ. The USB "
        "enabled-interface mask is the one record that changes what the token "
        "presents on the bus, and this is the one sub-command the client sends "
        "with no token and no MAC at all"
    )
    assert body == b"", (
        "a non-zero status carries no body at all: PicoForge parses the CBOR "
        "half only when status == 0 (HidTransport::read_cbor_response), so "
        "trailing bytes here would be a second, quieter bug. Got %s" % body.hex()
    )


def test_led_block_of_a_wrong_length_is_refused(device):
    """A block that is not 17 bytes is refused rather than zero-extended.

    On this wire a 16-byte blob and a 17-byte blob of zeros are different
    requests: the first is a block the caller got wrong, the second is "turn
    every status dark". Accepting and padding the first would make the two
    indistinguishable, and the second is a real configuration someone might
    legitimately want.
    """
    device.reset()
    token = _acfg_token(device)

    for blob, what in [
        (b"", "an empty blob"),
        (LED_BLOCK_EXAMPLE[:16], "a 16-byte block, one short"),
        (LED_BLOCK_EXAMPLE + b"\x00", "an 18-byte block, one long"),
    ]:
        status, _ = _config_write(device, token, TARGET_LED, blob)
        assert status != CTAP2_OK, (
            "%s was accepted. `RSKEY_LED_CONF_LEN` is 17 "
            "(picoforge/src/hal/fido/mod.rs:2001), and zero-extending a short "
            "block would make a malformed request indistinguishable on the wire "
            "from a valid one that turns every status dark" % what
        )
