"""US-163 (PICOForge-COMPAT) — Rescue REBOOT and SECURE.

Two commands, both unauthenticated, and both with a placement trap the client's
own documentation gets wrong:

* **REBOOT's mode is in P1, not P2.** The client's `RescueInstruction::Reboot`
  doc comment says P2 — *"P2 parameter determines reboot mode (0x00=Normal,
  0x01=Bootsel)"* (``picoforge/src/hal/rescue/constants.rs:143-145``) — and the
  code puts it in P1 (``ops.rs:646-652``), as do three other call sites. A
  device that implemented the comment would always normal-reboot, silently. The
  client's own ``reboot_device`` is ``#[allow(dead_code)]`` and never called, so
  nothing upstream would notice either way.
* **SECURE's lock byte is in P2** and P1 is a boot-key index — the exact inverse
  of REBOOT (``ops.rs:691-696``).

## Why no test here performs a real reboot

The emulation process *is* the card: there is no bootrom, no watchdog and no
BOOTSEL mass-storage interface to enter, and a process that actually exited
would take the whole pytest session's emulator with it. So the emulation's
``REBOOT`` handler records the request on stderr and answers ``9000`` without
rebooting, and **this file asserts against that log line** — both modes are
still exercised end to end over real CCID, the applet's decode of P1 is proven
by the recorded value, and nothing is lost except the thing that cannot be
done on a host at all.

On the **device** the same APDU does reboot: ``RESCUE_REBOOT_PENDING`` records
the mode, ``ccid_task`` performs the reset *after* the reply is written (so the
client's ``9000`` check succeeds first), and BOOTSEL goes through the RP2350
bootrom's own ``reboot2`` (``firmware/src/boot.rs``). The ordering is load
bearing: the client checks the status word (``ops.rs:653-656``), so a reset
that outran the reply would surface as a transport error on a command that in
fact succeeded.

## SECURE is dispatched and refused, not implemented

US-163 asks for it and this file proves the command is reachable and its P2
decoded. The device **refuses** it with ``6A86``, deliberately: nothing in this
firmware implements secure boot (threat model §0.3 — no secure-boot state, no
bootrom key, no verification step anywhere in the tree), so an unauthenticated
``80 1D 00 01 00`` that only refused future PHY writes would cost the owner a
permanent reconfiguration lockout and prevent no reflash at all. That is R9, and
§6.1 objection 1 is the argument for it. The client marks its own helper
``UNSTABLE`` and ``#[allow(dead_code)]`` and never calls it, so no host is
waiting on the answer.
"""

from harness.rescue_ccid import RescueEmu, reboot, secure


def test_reboot_and_secure_apis(tmp_path):
    """Both privileged commands are dispatched, decoded from the right byte, and
    acknowledged — without rebooting the emulator."""
    log = tmp_path / "rescue_reboot_emulator.log"
    with RescueEmu("reboot", tmp_path, log_path=log) as emu:
        _, sw = emu.select()
        assert sw == 0x9000

        # --- REBOOT, BOOTSEL (mode 0x01 in P1) -------------------------
        data, sw = emu.send(reboot(0x01))
        assert sw == 0x9000, f"REBOOT BOOTSEL must be accepted; got {sw:04X}"
        assert data == b"", f"REBOOT answers 9000 and nothing else; got {data.hex()}"

        # --- REBOOT, normal (mode 0x00 in P1) ---------------------------
        data, sw = emu.send(reboot(0x00))
        assert sw == 0x9000, f"REBOOT normal must be accepted; got {sw:04X}"
        assert data == b""

        # The emulator records what it decoded. Asserting on this is what
        # proves the **P1** placement: had the device read the mode from P2 —
        # the way the client's own doc comment says to — the BOOTSEL request
        # above would have been recorded as `mode=0`, indistinguishable from the
        # normal reboot, and this assertion would fail.
        text = emu.log()
        assert "rescue: REBOOT requested mode=1" in text, (
            "the BOOTSEL request (P1 = 0x01) must be recorded as mode 1. The "
            "mode is in P1 — ops.rs:646-652 — and the client's "
            "RescueInstruction::Reboot doc comment (constants.rs:143-145) "
            f"says P2, which is wrong. Emulator log:\n{text}"
        )
        assert "rescue: REBOOT requested mode=0" in text, (
            f"the normal request (P1 = 0x00) must be recorded as mode 0. "
            f"Emulator log:\n{text}"
        )
        # Ordering: BOOTSEL was asked for first, and the log must show that
        # order — a device that collapsed both modes onto one value would pass
        # the two `in` checks above with both lines reading "mode=0".
        assert text.index("mode=1") < text.index("mode=0"), (
            f"the BOOTSEL request was decoded after the normal one; the order "
            f"on the wire was BOOTSEL then normal. Emulator log:\n{text}"
        )

        # A mode the protocol does not define is refused, not clamped.
        data, sw = emu.send(reboot(0x02))
        assert sw == 0x6A86, (
            f"P1 = 0x02 is neither Normal nor Bootsel and must be refused with "
            f"6A86 — answering 9000 for a mode we did not perform is the same "
            f"class of lie the undestined-tag refusal prevents. Got {sw:04X}"
        )
        assert data == b""

        # REBOOT is case-3 with no data field: an off-length wire is refused,
        # because a frame with a body nobody looked at is a reboot the caller
        # did not intend.
        data, sw = emu.send(bytes([0x80, 0x1F, 0x01, 0x00, 0x00, 0x00]))
        assert sw == 0x6700, f"a 6-byte REBOOT must be a length refusal; got {sw:04X}"
        assert data == b""

        # The two refused frames must not have reached the owner: exactly two
        # REBOOT lines, for the two accepted requests.
        lines = [ln for ln in emu.log().splitlines() if "REBOOT requested" in ln]
        assert len(lines) == 2, (
            f"only the two well-formed REBOOT frames may reach the owner; got "
            f"{len(lines)}: {lines}"
        )

        # The applet is still reachable — nothing above took the device off the
        # bus, which is the property the harness depends on.
        _, sw = emu.send(reboot(0x00))
        assert sw == 0x9000
        _, sw = emu.select()
        assert sw == 0x9000

        # --- SECURE, lock (0x01 in P2) ----------------------------------
        data, sw = emu.send(secure(0x01))
        assert sw == 0x6A86, (
            f"SECURE must be dispatched and refused on this firmware: nothing "
            f"implements secure boot (threat model §0.3), so a lock that only "
            f"refused future PHY writes would cost the owner a permanent "
            f"reconfiguration lockout and prevent no reflash (R9). A different "
            f"status here would mean the owner is locked out of a device that "
            f"has nothing to unlock. Got {sw:04X}"
        )
        assert data == b""

        # --- SECURE, unlock (0x00 in P2) --------------------------------
        data, sw = emu.send(secure(0x00))
        assert sw == 0x6A86, (
            f"SECURE unlock is refused for the same reason — the command is "
            f"unimplemented, not merely locked. Got {sw:04X}"
        )
        assert data == b""

        # The lock byte really was read from P2 and the key index from P1: a
        # value that is neither lock nor unlock is refused too, and the owner
        # logged both frames it was handed.
        data, sw = emu.send(secure(0x02))
        assert sw == 0x6A86, f"an undefined lock byte must be 6A86; got {sw:04X}"
        assert data == b""

        # A non-zero boot-key index is passed through to the owner, not
        # refused: the protocol defines P1 as a key index and the client always
        # sends 0 (ops.rs:694), but nothing documents what another index means
        # and refusing one would make the command unreachable for a future
        # client that names a second key.
        data, sw = emu.send(secure(0x01, key_index=0x07))
        assert sw == 0x6A86, (
            f"a non-zero boot-key index must reach the owner (and be refused "
            f"there), not be refused by the applet. Got {sw:04X}"
        )

        text = emu.log()
        assert "rescue: SECURE key=0 lock=true" in text, (
            f"P2 = 0x01 must reach the owner as lock=true. Emulator log:\n{text}"
        )
        assert "rescue: SECURE key=0 lock=false" in text, (
            f"P2 = 0x00 must reach the owner as lock=false. Emulator log:\n{text}"
        )
        assert "rescue: SECURE key=7 lock=true" in text, (
            f"P1 must reach the owner as the boot-key index. Emulator log:\n{text}"
        )
        # The undefined lock byte never reached it: no `lock=` for a third
        # value, and only the three frames above were handed over.
        secure_lines = [ln for ln in text.splitlines() if "rescue: SECURE" in ln]
        assert len(secure_lines) == 3, (
            f"only well-formed SECURE frames reach the owner; got "
            f"{len(secure_lines)}: {secure_lines}"
        )


def test_privileged_commands_need_the_proprietary_cla(tmp_path):
    """`REBOOT` and `SECURE` are as CLA-gated as everything else.

    `0x1D` and `0x1F` are **also** Management INS values, and Management's own
    gate refuses a non-`0x00` CLA with `6E00`
    (``apps/mgmt/src/lib.rs:429-431``) — so a dispatch mistake can be refused
    but never mis-executed. This test covers the direction that is not already
    closed: a `CLA 0x00` APDU arriving at the **Rescue** applet, which is a
    real path because the Rescue SELECT is itself `CLA 0x00` (threat model
    §3.2).
    """
    with RescueEmu("reboot", tmp_path) as emu:
        emu.select()
        for cla in (0x00, 0x90, 0xA0):
            for ins in (0x1C, 0x1D, 0x1E, 0x1F):
                data, sw = emu.send(bytes([cla, ins, 0x01, 0x00, 0x00]))
                assert sw == 0x6E00, (
                    f"CLA {cla:#04x} INS {ins:#04x} must be refused with 6E00 "
                    f"before the INS is looked at; got {sw:04X}"
                )
                assert data == b""

        # Nothing reached the privileged owner.
        text = emu.log()
        assert "REBOOT requested" not in text, (
            f"a refused-CLA REBOOT must not reach the owner:\n{text}"
        )


def test_an_unknown_ins_is_refused(tmp_path):
    """`6D00` for anything outside the four — the set is enumeration, not vigilance."""
    with RescueEmu("reboot", tmp_path) as emu:
        emu.select()
        for ins in (0x00, 0x10, 0x1B, 0x20, 0xA4, 0xFF):
            data, sw = emu.send(bytes([0x80, ins, 0x01, 0x00, 0x00]))
            assert sw == 0x6D00, f"INS {ins:#04x} must be 6D00; got {sw:04X}"
            assert data == b""
        # The four real ones are unchanged.
        for ins, p1, p2 in ((0x1E, 0x02, 0x00), (0x1D, 0x00, 0x00), (0x1F, 0x00, 0x00)):
            _, sw = emu.send(bytes([0x80, ins, p1, p2, 0x00]))
            assert sw != 0x6D00, f"INS {ins:#04x} must still be dispatched"
