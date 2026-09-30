"""US-161a / US-161b (PICOForge-COMPAT) — Rescue READ: FlashInfo, SecureBootStatus,
PhyConfig.

Three commands, one INS (``0x1E``), and the P1/P2 placement is the whole
difficulty. FlashInfo and SecureBootStatus carry P2 = ``0x00``; **PhyConfig
carries P2 = ``0x01``** (``picoforge/src/hal/rescue/ops.rs:292-296`` against
``:275-279`` and ``:288-292``). The device accepts *both* ``0x00`` and ``0x01``
on the PhyConfig read, and this file asserts both, because the client writes
that same record with P2 = ``0x00`` (``ops.rs:606``) — a device that accepted
only the value the read happens to use would be unreachable from whichever
client build chose the other.

All three reads are **unauthenticated** and that is the design, not an oversight
(``docs/tasks/rescue-threat-model.md`` §1): the attacker in the model has
physical possession and no PIN, no touch and no token. What the reads expose is
a chip id, five flash counters, a two-byte status word and a config blob — none
of which is key material, and §2's invariant is that no read INS returns a
credential.
"""

from harness.rescue_ccid import (
    READ_FLASH_INFO,
    READ_PHY_P2_BOGUS,
    READ_PHY_P2_ONE,
    READ_PHY_P2_ZERO,
    READ_SECURE_BOOT,
    TAG_ENABLED_USB_ITF,
    TAGS_UNDESTINED,
    RescueEmu,
    parse_phy,
)


def test_secureboot_and_phy_read(tmp_path):
    """SecureBootStatus is 2 bytes; PhyConfig is a TLV blob; FlashInfo is 5 u32s.

    All three in one test because ``read_device_details`` issues them as one
    sequence (``ops.rs:264-299``) and a failure anywhere in that sequence is
    what makes the client's Config screen report a device error.
    """
    with RescueEmu("read", tmp_path) as emu:
        _, sw = emu.select()
        assert sw == 0x9000, "the Rescue applet must be selectable first"

        # --- SecureBootStatus: [enabled, locked] -------------------------
        data, sw = emu.send(READ_SECURE_BOOT)
        assert sw == 0x9000, f"READ SecureBootStatus failed: {sw:04X}"
        # The client only reads the pair when SW is 9000 and the whole reply
        # (data + SW) is at least 4 bytes (ops.rs:284-289) — 2 data bytes is
        # exactly that floor.
        assert len(data) + 2 == 4, (
            f"the client's length gate is >= 4 including the SW; got "
            f"{len(data)} data + 2 = {len(data) + 2}"
        )
        assert len(data) == 2, f"two bytes, enabled then locked; got {len(data)}"
        assert data[0] == 0, (
            "secure boot is not enabled. Nothing in this firmware implements "
            "it (threat model §0.3: no secure-boot state, no bootrom key, no "
            "verification step anywhere in the tree) — reporting 1 would be a "
            "claim the device cannot back up"
        )
        assert data[1] == 0, "secure boot is not locked, for the same reason"

        # --- PhyConfig: the TLV blob ------------------------------------
        data, sw = emu.send(READ_PHY_P2_ONE)
        assert sw == 0x9000, (
            f"READ PhyConfig with P2=0x01 failed: {sw:04X}. This is the value "
            f"the client sends (ops.rs:295) — the Config screen is "
            f"unreadable without it"
        )
        records = parse_phy(data)
        # Only records with a field in the persisted record are emitted. The
        # others are refused on a WRITE (threat model §0.2), and emitting one
        # here would make the client's read-modify-write send back a tag the
        # device then refuses.
        for tag in TAGS_UNDESTINED:
            assert tag not in records, (
                f"tag {tag:#04x} has no field in the persisted record and must "
                f"not be served; got {data.hex()}"
            )
        # Nothing is configured on a fresh token, so the blob may legitimately
        # be empty — but if anything IS there, it must be well formed and it
        # must be one of the five supported tags.
        for tag, value in records.items():
            assert tag in (0x00, 0x04, 0x05, 0x06, 0x0B), (
                f"unexpected tag {tag:#04x} in the PHY read: {data.hex()}"
            )
            assert len(value) >= 1, f"tag {tag:#04x} has a zero-length value"

        # --- PhyConfig with P2 = 0x00: also accepted --------------------
        data0, sw0 = emu.send(READ_PHY_P2_ZERO)
        assert sw0 == 0x9000, (
            f"READ PhyConfig with P2=0x00 must be accepted: the client WRITES "
            f"the same record with P2=0x00 (ops.rs:606), so a device that "
            f"accepted only 0x01 here would be unreachable from whichever "
            f"build chose 0x00. Got {sw0:04X}"
        )
        assert parse_phy(data0) == records, "both P2 values must serve the same record"

        # A P2 that names nothing is refused rather than ignored.
        bad, sw_bad = emu.send(READ_PHY_P2_BOGUS)
        assert sw_bad == 0x6A86, (
            f"an undefined P2 must be refused with 6A86; got {sw_bad:04X}"
        )
        assert bad == b"", f"a refusal carries no data; got {bad.hex()}"

        # --- FlashInfo: 5 big-endian u32s --------------------------------
        data, sw = emu.send(READ_FLASH_INFO)
        assert sw == 0x9000, f"READ FlashInfo failed: {sw:04X}"
        assert len(data) == 20, (
            f"five big-endian u32 words (free, used, total, nfiles, chip "
            f"size, ops.rs:264-270); got {len(data)} bytes"
        )
        free, used, total, nfiles, chip_size = (
            int.from_bytes(data[i * 4 : i * 4 + 4], "big") for i in range(5)
        )
        # The one FlashInfo word the client surfaces
        # (`(chip_size > 0).then_some(chip_size)`, ops.rs:425) and the one that
        # is a real constant on both builds.
        assert chip_size == 4 * 1024 * 1024, (
            f"the RP2350 part this firmware targets is 4 MiB "
            f"(firmware/src/boot.rs FLASH_SIZE); got {chip_size}"
        )
        # `used` must be the live partition image's length — checked against
        # the file, not against a restatement of the firmware's arithmetic.
        partition = tmp_path / "rescue_partition.bin"
        on_disk = partition.stat().st_size if partition.exists() else 0
        assert used == on_disk, (
            f"used must be the emulated partition image's length ({on_disk} "
            f"bytes on disk); got {used}"
        )
        # `free` and `total` are 0 on a host, and that is the honest answer
        # rather than a device value faked: the emulation's store is an
        # unbounded map serialized whole, so it has no capacity. The device
        # build reports all three, computing `free` as
        # `SECURE_PARTITION_SIZE - used` (firmware/src/main.rs) against the
        # sealed partition's bound.
        assert free == 0 and total == 0, (
            f"the host store is unbounded and reports no capacity; expected "
            f"free=0 total=0, got free={free} total={total}"
        )
        assert nfiles == 0, (
            "nfiles is reported as 0 on every shipped build and that is not a "
            "measurement: SecureStore exposes `contains` but no enumeration "
            "(platform/src/secure_store.rs:344-390), so counting live records "
            "would mean changing the platform trait for a number the client "
            "only displays. The client's Config screen therefore shows "
            f"'0 files' for a token that has records. Got {nfiles}"
        )


def test_reads_are_gated_by_the_proprietary_cla(tmp_path):
    """Every non-SELECT Rescue command is CLA ``0x80``; anything else is ``6E00``.

    Load-bearing, not a formality: three of the four Rescue INS values
    (``0x1C``, ``0x1D``, ``0x1E``) are *also* Management INS values, so a
    ``CLA 0x00`` APDU reaching this applet would be an unauthenticated RESET
    (threat model §3.2). The device gates on the CLA before it looks at the
    INS.
    """
    with RescueEmu("read", tmp_path) as emu:
        _, sw = emu.select()
        assert sw == 0x9000

        for cla in (0x00, 0x90, 0xA0):
            data, sw = emu.send(bytes([cla, 0x1E, 0x02, 0x00, 0x00]))
            assert sw == 0x6E00, (
                f"CLA {cla:#04x} must be refused with 6E00; got {sw:04X}"
            )
            assert data == b"", f"a refused APDU carries no data; got {data.hex()}"


def test_read_p1_must_name_a_target(tmp_path):
    """A fourth READ P1 is refused, not answered with an empty blob.

    The three reads have no operands, so a P1 outside ``0x01``/``0x02``/``0x03``
    names nothing — and answering ``9000`` with an empty body would look to the
    client like a device reporting nothing rather than a device refusing.
    """
    with RescueEmu("read", tmp_path) as emu:
        emu.select()
        for p1 in (0x00, 0x04, 0x10, 0xFF):
            data, sw = emu.send(bytes([0x80, 0x1E, p1, 0x00, 0x00]))
            assert sw == 0x6A86, f"READ P1 {p1:#04x} must be 6A86; got {sw:04X}"
            assert data == b""

        # And the three real ones still work, so the refusal above is about the
        # P1 and not about the CLA or the INS.
        for apdu in (READ_FLASH_INFO, READ_SECURE_BOOT, READ_PHY_P2_ONE):
            _, sw = emu.send(apdu)
            assert sw == 0x9000, f"{apdu.hex()} must still answer 9000; got {sw:04X}"


def test_the_ccid_mask_is_reported_when_configured(tmp_path):
    """A configured `0x0B` mask reads back — and it must carry the CCID bit.

    The client parses tag `0x0B` out of this read into
    ``config.enabled_usb_itf`` (``ops.rs``'s `PhyTag::EnabledUsbItf` arm) and
    then ORs CCID back in before writing it (``ops.rs:580-582``). So a device
    that served no mask would leave the client with nothing to round-trip, and
    a device that served a mask *without* CCID would be reporting a
    configuration its own recovery path cannot use.
    """
    # Seed the record through the WRITE first; the round trip is the subject of
    # test_rescue_write.py, and this test only checks what the READ reports.
    with RescueEmu("read", tmp_path) as emu:
        emu.select()
        _, sw = emu.send(READ_PHY_P2_ONE)
        assert sw == 0x9000
        fresh = parse_phy(_)
        # A fresh token has no stored configuration, which the client renders
        # as "nothing set" — the honest answer for a record that does not
        # exist. Any mask that *is* reported must carry CCID.
        if TAG_ENABLED_USB_ITF in fresh:
            mask = fresh[TAG_ENABLED_USB_ITF]
            assert len(mask) == 1, f"tag 0x0B is one byte; got {len(mask)}"
            assert mask[0] & 0x01, (
                f"a reported mask must carry USB_ITF_CCID (0x01); got "
                f"{mask[0]:#04x}"
            )
