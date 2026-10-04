"""US-162 (PICOForge-COMPAT) — Rescue WRITE PhyConfig, and the CCID-mask guard.

The write is the whole of the risk in this phase, and this file is where it is
pinned. Three properties, in the order they matter:

1. **The CCID-mask guard.** Tag ``0x0B`` must never lose bit ``0x01``
   (``USB_ITF_CCID``). The client volunteers this on our behalf — *"SAFETY:
   Never write a mask without CCID, otherwise Rescue applet is unreachable"*
   (``picoforge/src/hal/rescue/ops.rs:580-582``) — but a client-side courtesy
   is not a control on a surface that exists precisely because the client is
   not in the trust boundary. Without the device-side rule, six bytes
   (``80 1C 01 00 03 0B 01 00``) write a zero mask, the device re-enumerates
   with no CCID interface, and the applet that performed the write can no
   longer be reached to undo it.
2. **It is a merge, not a replace** — *"an omitted tag is preserved"*
   (``ops.rs:584-585``) — so a one-record write changes exactly one field.
3. **The seven tags this firmware cannot store are refused whole.** There is no
   field for them in the persisted record (threat model §0.2), and
   accepted-and-ignored is not available: the client's reader skips a tag it
   does not know, so a dropped record would be reported as a successful
   configuration change (threat model §10.3).

The guard is a **safety** property, not a security one, and that distinction is
the point: nothing about a cleared mask discloses a credential. It protects the
operator's ability to recover their own device.
"""

from harness.rescue_ccid import (
    TAG_ENABLED_USB_ITF,
    TAG_LED_BRIGHTNESS,
    TAG_LED_GPIO,
    TAG_OPTIONS,
    TAG_VIDPID,
    TAGS_UNDESTINED,
    USB_ITF_CCID,
    USB_ITF_HID,
    USB_ITF_WCID,
    RescueEmu,
    parse_phy,
    tlv,
    write_phy,
)

#: Masks that keep CCID and therefore must be accepted.
MASKS_WITH_CCID = (0x01, 0x05, 0x07, 0x1F, 0xFF)
#: Masks that drop CCID and therefore must be refused — including ``0x02``
#: (WCID only), which is non-zero and is exactly the case the `0x41` path's
#: `zero_mask_refusal` lets through (`apps/fido/src/vendor41.rs:1409-1415`).
#: The Rescue guard is strictly stronger: it requires bit 0x01 to be
#: *retained*, not merely the mask to be non-zero (threat model §7).
MASKS_WITHOUT_CCID = (0x00, 0x02, 0x04, 0x10, 0xFE)


def test_phy_write_roundtrips(tmp_path):
    """A write merges into the record, the read reports it, and a restart keeps it."""
    with RescueEmu("write", tmp_path) as emu:
        _, sw = emu.select()
        assert sw == 0x9000

        # Baseline: whatever a fresh token reports.
        baseline, sw = emu.send(bytes([0x80, 0x1E, 0x01, 0x01, 0x00]))
        assert sw == 0x9000
        before = parse_phy(baseline)

        # A single-record write, in the form the client sends it. The mask
        # carries CCID, exactly as the client ORs it in before writing.
        data, sw = emu.send(
            write_phy(tlv((TAG_ENABLED_USB_ITF, bytes([USB_ITF_CCID | USB_ITF_WCID]))))
        )
        assert sw == 0x9000, f"the CCID-retaining mask must be accepted; got {sw:04X}"
        assert data == b"", f"a successful WRITE answers 9000 and nothing else; got {data.hex()}"

        # Read back over the wire: the mask is there and the CCID bit is set.
        blob, sw = emu.send(bytes([0x80, 0x1E, 0x01, 0x01, 0x00]))
        assert sw == 0x9000
        records = parse_phy(blob)
        assert TAG_ENABLED_USB_ITF in records, (
            f"the mask must read back; got {blob.hex()}"
        )
        assert records[TAG_ENABLED_USB_ITF][0] == (USB_ITF_CCID | USB_ITF_WCID), (
            f"mask round trip: expected {USB_ITF_CCID | USB_ITF_WCID:#04x}, got "
            f"{records[TAG_ENABLED_USB_ITF][0]:#04x}"
        )

        # It is a MERGE: nothing else moved.
        for tag, value in before.items():
            if tag == TAG_ENABLED_USB_ITF:
                continue
            assert records.get(tag) == value, (
                f"tag {tag:#04x} was not in the write blob and must be "
                f"preserved (ops.rs:584-585): was {value!r}, now "
                f"{records.get(tag)!r}"
            )


def test_a_write_is_durable_across_an_emulator_restart(tmp_path):
    """The `9000` follows the store write, so the record survives a restart.

    This is the durable-before-ack property stated as a harness fact. The
    emulation's Rescue record is a file stand-in for the device's FIDO-keystore
    auth-map key 6 (``firmware/src/boot.rs``), and the device owner persists
    before answering too — a `9000` that outran the store write would tell an
    operator a configuration change is durable when it is not, and this applet
    exists for recovery.
    """
    # The same tmp_path across two emulator lifetimes is what makes this a
    # restart rather than a fresh boot. Every field is written, so a stand-in
    # that silently dropped one would show up here as a missing record.
    seed = tlv(
        (TAG_VIDPID, bytes([0xFA, 0x20, 0x00, 0x07])),
        (TAG_LED_GPIO, bytes([0x0C])),
        (TAG_LED_BRIGHTNESS, bytes([73])),
        (TAG_OPTIONS, bytes([0x00, 0x06])),
        (TAG_ENABLED_USB_ITF, bytes([USB_ITF_CCID | USB_ITF_HID])),
    )
    for attempt in (1, 2):
        with RescueEmu("write", tmp_path) as emu:
            _, sw = emu.select()
            assert sw == 0x9000
            if attempt == 1:
                data, sw = emu.send(write_phy(seed))
                assert sw == 0x9000, f"write failed: {sw:04X}"
                continue
            blob, sw = emu.send(bytes([0x80, 0x1E, 0x01, 0x01, 0x00]))
            assert sw == 0x9000
            records = parse_phy(blob)
            for tag in (TAG_VIDPID, TAG_LED_GPIO, TAG_LED_BRIGHTNESS, TAG_OPTIONS,
                        TAG_ENABLED_USB_ITF):
                assert tag in records, (
                    f"tag {tag:#04x} was written before the restart and must "
                    f"still be there; got {blob.hex()}"
                )
            assert records[TAG_VIDPID] == bytes([0xFA, 0x20, 0x00, 0x07])
            assert records[TAG_LED_GPIO] == bytes([0x0C])
            assert records[TAG_LED_BRIGHTNESS] == bytes([73])
            assert records[TAG_OPTIONS] == bytes([0x00, 0x06])
            assert records[TAG_ENABLED_USB_ITF] == bytes(
                [USB_ITF_CCID | USB_ITF_HID]
            )


def test_ccid_mask_guard_refuses_a_mask_that_drops_ccid(tmp_path):
    """Every mask without bit 0x01 is refused — and refused **whole**."""
    with RescueEmu("write", tmp_path) as emu:
        emu.select()
        # Seed a state worth protecting: a mask WITH CCID and a brightness.
        _, sw = emu.send(write_phy(tlv((TAG_ENABLED_USB_ITF, bytes([0x05])))))
        assert sw == 0x9000
        _, sw = emu.send(write_phy(tlv((TAG_LED_BRIGHTNESS, bytes([50])))))
        assert sw == 0x9000

        for mask in MASKS_WITHOUT_CCID:
            # A benign record rides along in the same blob. If the device
            # applied-as-it-parsed, that record would land even though the mask
            # is refused; asserting it did not is the "whole" in "refused
            # whole".
            _, sw = emu.send(
                write_phy(
                    tlv(
                        (TAG_ENABLED_USB_ITF, bytes([mask])),
                        (TAG_LED_GPIO, bytes([0x11])),
                    )
                )
            )
            assert sw == 0x6A80, (
                f"mask {mask:#04x} drops USB_ITF_CCID and must be refused with "
                f"6A80 (the value conflicts with a device requirement); got "
                f"{sw:04X}. The minimal brick is `80 1C 01 00 03 0B 01 00`"
            )

        # Nothing moved: the mask still has CCID, the brightness is untouched,
        # and the LED GPIO was never applied.
        blob, sw = emu.send(bytes([0x80, 0x1E, 0x01, 0x01, 0x00]))
        assert sw == 0x9000
        records = parse_phy(blob)
        assert records[TAG_ENABLED_USB_ITF][0] & USB_ITF_CCID, (
            f"the stored mask must still carry CCID; got "
            f"{records[TAG_ENABLED_USB_ITF][0]:#04x}"
        )
        assert records[TAG_LED_BRIGHTNESS] == bytes([50]), (
            f"an unrelated record in a refused blob must not be applied; got "
            f"{records.get(TAG_LED_BRIGHTNESS)!r}"
        )
        assert TAG_LED_GPIO not in records or records[TAG_LED_GPIO] != bytes(
            [0x11]
        ), "the 0x04 record in a refused blob must not be applied"


def test_ccid_mask_guard_is_stricter_than_the_zero_mask_rule(tmp_path):
    """`0x02` (WCID, no CCID) is non-zero and is still refused.

    ``apps/fido``'s `0x41` path refuses exactly one value — ``0``
    (``zero_mask_refusal_value``, ``apps/fido/src/vendor41.rs:1409-1415``) —
    and would accept ``0x02``. On this surface ``0x02`` is equally a brick,
    because CCID *is* the Rescue applet's own transport. The two rules must not
    converge (threat model §9 tripwire 4), and this is the test that says so.
    """
    with RescueEmu("write", tmp_path) as emu:
        emu.select()
        _, sw = emu.send(write_phy(tlv((TAG_ENABLED_USB_ITF, bytes([0x02])))))
        assert sw == 0x6A80, (
            "a non-zero mask with no CCID bit is still refused: the rule is "
            f"'bit 0x01 must be retained', not 'the mask must be non-zero'. "
            f"Got {sw:04X}"
        )


def test_every_mask_retaining_ccid_is_accepted(tmp_path):
    """The guard constrains one bit, not the mask."""
    with RescueEmu("write", tmp_path) as emu:
        emu.select()
        for mask in MASKS_WITH_CCID:
            data, sw = emu.send(
                write_phy(tlv((TAG_ENABLED_USB_ITF, bytes([mask]))))
            )
            assert sw == 0x9000, f"mask {mask:#04x} retains CCID; got {sw:04X}"
            assert data == b""
            blob, _ = emu.send(bytes([0x80, 0x1E, 0x01, 0x01, 0x00]))
            assert parse_phy(blob)[TAG_ENABLED_USB_ITF][0] == mask


def test_the_five_unsupported_tags_are_skipped_and_the_rest_applied(tmp_path):
    """A tag this build does not model is skipped; the records beside it apply.

    This applet used to refuse the **whole blob** with ``6A86`` on the first
    tag it had no field for. Both references skip instead: RS-Key's ``overlay``
    ends in a terminal ``_ => {}`` and returns ``PhyData``, not ``Result``, so
    no tag can fail a write (``rsk-phy/src/lib.rs:270``); pico-keys-sdk's
    ``phy_unserialize_data`` has ``default: break;`` (``fs/phy.c:170-182``).

    Refusing cost a real user every configuration change, because picoforge
    synthesises a ``Curves`` record whenever the device reports none — see
    :func:`test_the_picoforge_vendor_preset_saves`.
    """
    values = {
        0x08: b"\x0a",              # PresenceTimeout, 1 byte
        0x0A: b"\x00\x00\x00\x01",  # Curves, u32 BE
        0x0C: b"\x01",              # LedDriver
        0x0D: b"\x01",              # LedOrder
        0x0E: b"\x04",              # LedNum
    }
    assert set(values) == set(TAGS_UNDESTINED)

    with RescueEmu("write", tmp_path) as emu:
        emu.select()
        _, sw = emu.send(write_phy(tlv((TAG_LED_BRIGHTNESS, bytes([11])))))
        assert sw == 0x9000, "seed a known state first"

        for tag, value in values.items():
            data, sw = emu.send(
                write_phy(
                    tlv(
                        (tag, value),
                        (TAG_LED_GPIO, bytes([0x22])),
                    )
                )
            )
            assert sw == 0x9000, (
                f"tag {tag:#04x} has no field here, but that must not cost the "
                f"operator the record beside it. Got {sw:04X}"
            )
            assert data == b""

        blob, sw = emu.send(bytes([0x80, 0x1E, 0x01, 0x01, 0x00]))
        assert sw == 0x9000
        records = parse_phy(blob)
        assert records[TAG_LED_BRIGHTNESS] == bytes([11]), (
            "the seed must survive the writes that skipped a tag"
        )
        assert records.get(TAG_LED_GPIO) == bytes([0x22]), (
            f"the 0x04 record beside a skipped tag {tag:#04x} must be applied"
        )


def test_the_picoforge_vendor_preset_saves(tmp_path):
    """The reported scenario, end to end over CCID: YubiKey 5, 1050:0407.

    picoforge — which we neither control nor fork — synthesises a ``Curves``
    (``0x0A``) record whenever the device reports none, so **every**
    configuration save it makes carries one. Before this applet learned to skip
    an unsupported tag, that single record discarded the whole blob and the
    operator saw ``Write failed: [6A, 86]`` with the status word reading like a
    P1/P2 complaint.

    The APDU below is built the way picoforge builds it (``ops.rs``: tag/len
    TLVs, ``1050`` and ``0407`` parsed from the preset's hex and written
    big-endian as ``vid:u16 BE, pid:u16 BE``), plus the ``0x0A`` it always
    emits. The assertion is the one the user cares about: afterwards, a
    ``PhyConfig`` READ reports the new identity.
    """
    vid, pid = 0x1050, 0x0407  # "YubiKey 5 (1050:0407)"
    vid_pid = bytes([TAG_VIDPID, 0x04,
                     (vid >> 8) & 0xFF, vid & 0xFF,
                     (pid >> 8) & 0xFF, pid & 0xFF])
    curves = bytes([0x0A, 0x04, 0x00, 0x00, 0x00, 0x00])  # mask 0, no toggles

    # The same tmp_path across two emulator lifetimes is what makes the second
    # a restart rather than a fresh boot — the discipline
    # `test_a_write_is_durable_across_an_emulator_restart` uses.
    for attempt in (1, 2):
        with RescueEmu("write", tmp_path) as emu:
            _, sw = emu.select()
            assert sw == 0x9000
            if attempt == 1:
                # The blob exactly as picoforge builds it for this save.
                data, sw = emu.send(write_phy(vid_pid + curves))
                assert sw == 0x9000, (
                    "the vendor preset save must succeed. The Curves record is "
                    "one this build does not model and must be skipped, not "
                    f"refused. Got {sw:04X} ({data.hex()})"
                )
                continue
            # The point of the operation: the device reports the new identity,
            # and it still does after a restart.
            read, sw = emu.send(bytes([0x80, 0x1E, 0x01, 0x01, 0x00]))
            assert sw == 0x9000
            records = parse_phy(read)
            assert records.get(TAG_VIDPID) == bytes([0x10, 0x50, 0x04, 0x07]), (
                "the PhyConfig READ must report 1050:0407 after the write, and "
                f"after a restart. Got {records.get(TAG_VIDPID)!r}"
            )


def test_a_write_round_trips_every_supported_record(tmp_path):
    """All five records apply at the widths and byte order the client writes.

    VID/PID and the options word are big-endian (``ops.rs:470-520``); the rest
    are one byte.
    """
    with RescueEmu("write", tmp_path) as emu:
        emu.select()
        blob = tlv(
            (TAG_VIDPID, bytes([0xFA, 0x20, 0x00, 0x03])),
            (TAG_LED_GPIO, bytes([0x19])),
            (TAG_LED_BRIGHTNESS, bytes([100])),
            (TAG_OPTIONS, bytes([0x00, 0x0A])),
            (TAG_ENABLED_USB_ITF, bytes([USB_ITF_CCID | USB_ITF_HID])),
        )
        data, sw = emu.send(write_phy(blob))
        assert sw == 0x9000, f"a five-record write must be accepted; got {sw:04X}"

        read_back, sw = emu.send(bytes([0x80, 0x1E, 0x01, 0x01, 0x00]))
        assert sw == 0x9000
        records = parse_phy(read_back)
        assert records[TAG_VIDPID] == bytes([0xFA, 0x20, 0x00, 0x03]), (
            f"VID/PID is 4 bytes big-endian; got {records[TAG_VIDPID]!r}"
        )
        assert records[TAG_LED_GPIO] == bytes([0x19])
        assert records[TAG_LED_BRIGHTNESS] == bytes([100])
        assert records[TAG_OPTIONS] == bytes([0x00, 0x0A]), (
            f"the options word is 2 bytes big-endian; got {records[TAG_OPTIONS]!r}"
        )
        assert records[TAG_ENABLED_USB_ITF] == bytes([USB_ITF_CCID | USB_ITF_HID])


def test_malformed_writes_are_refused_on_their_own_terms(tmp_path):
    """Each malformed shape gets the status that means *that* thing.

    A single status word covering several distinct problems makes a device log
    unreadable, so the separation is the assertion: ``6700`` is a length,
    ``6A86`` is a value or a target this build does not serve, ``6A80`` is a
    value that would brick the applet.
    """
    with RescueEmu("write", tmp_path) as emu:
        emu.select()
        cases = [
            # (apdu, expected SW, what it is)
            (bytes([0x80, 0x1C, 0x01, 0x00, 0x04, 0x00, 0x04, 0xFA]),
             0x6700, "a TLV value that runs past the end of the blob"),
            (bytes([0x80, 0x1C, 0x01, 0x00, 0x01, 0x04]),
             0x6700, "a tag byte with no length byte"),
            (bytes([0x80, 0x1C, 0x01, 0x00, 0x05, 0x0B, 0x03, 0x00, 0x00, 0x00]),
             0x6700, "a 3-byte 0x0B record: a width problem, NOT a mask problem"),
            (bytes([0x80, 0x1C, 0x01, 0x00, 0x03, 0x0B, 0x01, 0x00]),
             0x6A80, "a 1-byte 0x0B record with a zero mask: a value problem"),
            (bytes([0x80, 0x1C, 0x02, 0x00, 0x03, 0x05, 0x01, 0x32]),
             0x6A86, "a WRITE P1 that names nothing"),
            (bytes([0x80, 0x1C, 0x01, 0x01, 0x03, 0x05, 0x01, 0x32]),
             0x6A86, "a WRITE P2 of 0x01: the WRITE's P2 is 0x00, unlike the read's"),
            (bytes([0x80, 0x1C, 0x01, 0x00, 0x10, 0x05, 0x01, 0x32]),
             0x6700, "an Lc longer than the data that arrived"),
            (bytes([0x80, 0x1C, 0x01, 0x00]),
             0x6700, "a WRITE with no Lc byte at all"),
        ]
        for apdu, expected, what in cases:
            data, sw = emu.send(apdu)
            assert sw == expected, (
                f"{what}: {apdu.hex()} should answer {expected:04X}, got {sw:04X}"
            )
            assert data == b"", f"a refusal carries no data; got {data.hex()}"


def test_an_empty_blob_is_a_legal_no_op_merge(tmp_path):
    """`Lc = 0` is a merge that changes nothing, and it succeeds."""
    with RescueEmu("write", tmp_path) as emu:
        emu.select()
        _, sw = emu.send(write_phy(tlv((TAG_LED_BRIGHTNESS, bytes([42])))))
        assert sw == 0x9000
        data, sw = emu.send(bytes([0x80, 0x1C, 0x01, 0x00, 0x00]))
        assert sw == 0x9000, f"an empty blob is a legal empty merge; got {sw:04X}"
        assert data == b""
        blob, sw = emu.send(bytes([0x80, 0x1E, 0x01, 0x01, 0x00]))
        assert parse_phy(blob)[TAG_LED_BRIGHTNESS] == bytes([42]), (
            "the empty merge must not have disturbed the record"
        )
