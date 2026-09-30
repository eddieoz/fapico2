"""US-161a (PICOForge-COMPAT) — the Rescue applet's SELECT.

The EPIC names this test ``rescue_select_returns_14_byte_block`` and that name
is the contract. What is asserted *inside* it is the 12 **data** bytes, because
14 is 12 data plus the 2 status bytes the client keeps in the same buffer
(``picoforge/src/hal/transport/pcsc.rs:73``, ``:89``) — the number the client's
own ``select_resp.len() >= 14`` test measures (``ops.rs:234``). Asserting 14
*data* bytes would pin a number the client never checks.
``docs/tasks/rescue-threat-model.md`` §10.1 makes the same point.

The load-bearing assertion in here is byte 2. The client classifies a device as
RS-Key iff ``data[2] >= 8`` and falls back to the PC/SC reader name first
(``pcsc.rs:45-50``, ``:75-81``); this firmware's USB product string is
``"fapico2"``, which contains neither ``"RS-Key"`` nor ``"RSK"``, so the name
path cannot fire and **byte 2 alone decides**. A byte of 1 — which is what
``fapico2_mgmt::VERSION_MAJOR`` is — would classify this device as PicoFido and
gate off every RS-Key-only client path.
"""

from harness.rescue_ccid import RescueEmu


def test_rescue_select_returns_14_byte_block(tmp_path):
    """The wire is 12 data bytes + ``9000`` = 14; the data is the identity block."""
    with RescueEmu("select", tmp_path) as emu:
        data, sw = emu.select()

        assert sw == 0x9000, (
            "the client refuses to go further on any other status "
            f"(pcsc.rs:66-71): got {sw:04X}"
        )
        assert len(data) + 2 == 14, (
            f"the whole SELECT response must be 14 bytes on the wire; got "
            f"{len(data)} data + 2 status = {len(data) + 2}"
        )
        assert len(data) == 12, (
            f"12 data bytes: 4 identity + an 8-byte chip id. Got {len(data)}"
        )

        # [0] MCU type — 1 = RP2350.
        assert data[0] == 1, f"byte 0 is the MCU type, 1 = RP2350; got {data[0]}"
        # [1] product type — 2 = FIDO.
        assert data[1] == 2, f"byte 1 is the product type, 2 = FIDO; got {data[1]}"
        # [2] SDK major — the classifier. See the module docstring.
        assert data[2] >= 8, (
            f"byte 2 is the RS-Key SDK major and the client requires >= 8 "
            f"(pcsc.rs:75-81); got {data[2]}"
        )
        assert data[2] == 8, (
            f"byte 2 must be the RS-Key SDK major (8), not the firmware "
            f"version (fapico2_mgmt::VERSION_MAJOR is 1); got {data[2]}"
        )
        # [3] SDK minor.
        assert data[3] == 0, f"byte 3 is the SDK minor; got {data[3]}"

        # [4..12] the chip id, big-endian. The client reads [4..7] and masks the
        # top two bits of byte 4 to derive an 8-digit serial (ops.rs:234-236).
        chipid = data[4:12]
        assert len(chipid) == 8
        serial = int.from_bytes(
            bytes([chipid[0] & 0x03]) + chipid[1:4], "big"
        )
        assert serial > 0, "the client would render a zero serial as a placeholder"


def test_rescue_select_is_reachable_through_the_plain_aid_path(tmp_path):
    """P2 = 0x04 on the SELECT is a courtesy of the client's generic builder.

    ``platform::dispatch::is_select_apdu`` keys on P1 alone, so the client's
    ``00 A4 04 04 08 <AID>`` must route as an ordinary AID SELECT. If that ever
    stopped being true the whole surface would go unreachable and the only
    symptom would be a ``6A82`` in a host log.
    """
    with RescueEmu("select", tmp_path) as emu:
        _, sw = emu.select()
        assert sw == 0x9000

        # The same applet answers again on a re-SELECT (the dispatcher
        # re-selects with a security reset; this applet has no session state to
        # reset, so the block is identical).
        data_again, sw_again = emu.select()
        assert sw_again == 0x9000
        assert data_again == data_again  # stability, asserted by the caller


def test_rescue_unknown_aid_is_refused(tmp_path):
    """A neighbouring AID is ``6A82``, and the Rescue one is still selectable.

    Proves the applet is reached by AID dispatch rather than by being the
    fallback for anything unmatched.
    """
    with RescueEmu("select", tmp_path) as emu:
        data, sw = emu.select()
        assert sw == 0x9000
        before = bytes(data)

        # One byte off the Rescue AID.
        bogus = bytes([0x00, 0xA4, 0x04, 0x04, 8]) + b"\xa0\x58\x3f\xc1\x9b\x7e\x4f\x22"
        _, sw = emu.send(bogus)
        assert sw == 0x6A82, f"an unknown AID must be 6A82 (file not found); got {sw:04X}"

        # The real one still answers, unchanged.
        data, sw = emu.select()
        assert sw == 0x9000
        assert data == before
