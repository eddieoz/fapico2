"""US-1708 — the generation cross-tolerance matrix, both directions.

Alpha users will hit new extension ↔ old firmware and old extension ↔ new
firmware. The emulator serves Nostr over CCID only (AGENTS.md §8), so the
matrix rides the CCID harness against BOTH images:

  new client ↔ old firmware (v0.2.0 image, worktree at ddc3875)
    - GET_INFO answers the same 8-byte shape, with the flags byte a
      reserved 0x00 (measured on the image: `00 01 00 03 07 00 00 00`) and
      caps without CAP_PIN_MGMT — the capability gate renders the
      unsupported state, not an error.
    - the PIN verbs (0x1B/0x1C/0x1D) are unmapped INS values → 6D00 IN BAND.
      Over the vendor HID the same story is byte 0x4B → the CBOR `sw`
      field; the firmware host tests pin that arm (the emulator never had
      the vendor-HID Nostr interface).

  old client ↔ new firmware
    - EXPORT (INS 0x1A) is retired → 6D00 in band, rendered as "export
      removed" by the custody UI.
    - GET_INFO answers the 8-byte body; the old client reads the first 7
      bytes it knows and never sees the flags byte move anything.

The in-band 6D00 property is the whole story: never a hang, never a
CTAPHID-level error, never a dropped frame.
"""

import os
from pathlib import Path

import pytest

from nostr_ccid import NOSTR_AID, NostrEmu, apdu

OLD_FW_BINARY = Path(
    os.environ.get(
        "FAPICO2_V020_EMULATION",
        "/tmp/fapico2-v020/target/x86_64-unknown-linux-gnu/debug/fapico2-emulation",
    )
)

INS_GET_INFO = 0x10
INS_EXPORT_KEY = 0x1A  # retired by US-1699
INS_VERIFY_PIN = 0x1B  # new
INS_SET_PIN = 0x1C
INS_LOCK = 0x1D
SW_INS_NOT_SUPPORTED = 0x6D00
SW_OK = 0x9000


@pytest.fixture(scope="module")
def old_emu(tmp_path_factory):
    if not OLD_FW_BINARY.exists():
        pytest.skip(
            f"the v0.2.0 image is not built at {OLD_FW_BINARY} — build the "
            "worktree at ddc3875 (recorded in docs/release-notes-alpha-v0.3.0.md)"
        )
    tmp = tmp_path_factory.mktemp("v020")
    with NostrEmu("select", tmp, binary=OLD_FW_BINARY) as e:
        yield e


@pytest.fixture(scope="module")
def new_emu(tmp_path_factory):
    repo_bin = (
        Path(__file__).resolve().parents[2]
        / "target"
        / "x86_64-unknown-linux-gnu"
        / "debug"
        / "fapico2-emulation"
    )
    if not repo_bin.exists():
        pytest.skip("the current fapico2-emulation is not built")
    tmp = tmp_path_factory.mktemp("current")
    with NostrEmu("keymgmt", tmp, binary=repo_bin) as e:
        yield e


def test_new_client_old_firmware_get_info_is_the_7_byte_body(old_emu):
    assert old_emu.select()[1] == SW_OK
    data, sw = old_emu.send(apdu(INS_GET_INFO))
    assert sw == SW_OK
    assert data == bytes.fromhex("0001000307000000"), (
        "v0.2.0 GET_INFO: applet_ver (0,1), caps 0x0003, max_plaintext 0x0700, "
        "n=0, and the flags byte a reserved 0x00"
    )
    caps = (data[2] << 8) | data[3]
    assert caps & 0x0004 == 0, "no CAP_PIN_MGMT — the capability gate hides the PIN UI"


def test_new_client_old_firmware_pin_verbs_answer_6d00_in_band(old_emu):
    assert old_emu.select()[1] == SW_OK
    for ins in (INS_VERIFY_PIN, INS_SET_PIN, INS_LOCK):
        data, sw = old_emu.send(apdu(ins, data=b"731742"))
        assert sw == SW_INS_NOT_SUPPORTED, f"INS {ins:#04x} answered {sw:#06x}"
        assert data == b"", "in band and empty — never a hang, never a dropped frame"


def test_old_client_new_firmware_export_answers_6d00_in_band(new_emu):
    assert new_emu.select()[1] == SW_OK
    data, sw = new_emu.send(apdu(INS_EXPORT_KEY, data=b"\x00"))
    assert sw == SW_INS_NOT_SUPPORTED
    assert data == b""


def test_old_client_new_firmware_get_info_still_parses(new_emu):
    assert new_emu.select()[1] == SW_OK
    data, sw = new_emu.send(apdu(INS_GET_INFO))
    assert sw == SW_OK
    assert len(data) == 8, "the 8-byte shape both generations share"
    assert data[7] == 0x00, "flags byte 0x00 — a PIN-less board is byte-compatible with the old read"


def test_both_generations_speak_the_same_envelope(old_emu, new_emu):
    # LIST_KEYS (INS 0x11) is pre-custody and identical on both: the matrix's
    # control row — a green op both ways.
    for e in (old_emu, new_emu):
        assert e.select()[1] == SW_OK
        data, sw = e.send(apdu(0x11))
        assert sw == SW_OK
        assert data[:1] == b"\x00", "n_identities = 0 on a fresh image"
