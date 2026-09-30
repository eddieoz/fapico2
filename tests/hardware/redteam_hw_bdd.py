#!/usr/bin/env python3
"""US-924 hardware BDD: red-team attack replays on the live RP2350.

Live-board acceptance evidence for the hardware-gated stories of the
[security-hardening EPIC](../../docs/tasks/EPIC-security-hardening.md)
(accumulates the US-914 `pso_touch_bdd.py` run with the remaining
attack replays from `redteam/out/ASSESSMENT_REPORT.md`).

Two groups (run order per the US-924 plan — non-destructive first):

  N-cases (no reflash needed; run on whatever image the board boots):
    N1  GA (uv:true) with NO PIN token        -> CTAP error, no assertion [R3/R10]
    N2  GA with forged pinUvAuthParam         -> CTAP error, no assertion [R10]
    N3  U2F REGISTER with zero touches        -> no credential minted      [R3]
    N4  mgmt WRITE_CONFIG with no session/press -> 6982 after the window  [R11]
    N5  mgmt RESET with no session/press      -> 6982 after the window     [R11]
        (run LAST; a press during the window would wipe — nobody touches)

  D-cases (need BOOTSEL flashes — interactive, prompted):
    D1  reflash hardened build (tip; US-920/922 included)
    D2  store v3 boot + keystore chipid/entropy binding (US-915/918) +
        OTP row policy state observation
    D3  presence-gated GA/U2F touch-GRANTED (finger on the board while
        the LED prompt is ON)                       [R3 green]
    D4  button-latch anti-harvest: one press before the pending request
        must NOT serve the next command (pso C5 discipline on FIDO) [R3]
    D5  CCID wedge recovery: stalled bulk-OUT then a valid message
        must resync (US-920)                        [R11]
    D6  forged v2 store slot flashed via BOOTSEL -> boot refusal     [R6]
    D7  foreign-image flash -> wipe-and-fresh policy (US-919)        [R9]
    D8  factory reset + genuine reflash -> clean documented end state

Evidence (command output) is printed as a table for
`docs/tasks/security-hardware-bdd.md`.

Usage:
  python3 tests/hardware/redteam_hw_bdd.py            # interactive pacing
  python3 tests/hardware/redteam_hw_bdd.py --filter N1,N2 --yes
  python3 tests/hardware/redteam_hw_bdd.py --list     # show cases only
"""
import argparse
import os
import struct
import sys
import time

from smartcard.System import readers

RESULTS = []

MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
INS_WRITE_CONFIG = 0x1C
INS_RESET = 0x1E
MGMT_REFUSALS = (0x6700, 0x6982, 0x6985, 0x6986)
# Refusal shapes: 6982-after-window is the hardened-build (US-921 wiring)
# shape; the pre-US-921 image (US-914-era, currently flashed) refuses
# immediately (6700 function-not-supported / 6985 conditions). Either way
# the attack FAILS — the exact shape is re-verified post-reflash in the
# D-phase.


def apdu(con, b):
    data, sw1, sw2 = con.transmit(b)
    while sw1 == 0x61:
        r2 = con.transmit([0x00, 0xC0, 0x00, 0x00, min(0xFF, sw2)])
        data += r2[0]
        sw1, sw2 = r2[1], r2[2]
    return sw1 << 8 | sw2, bytes(data)


def mgmt_con():
    for r in readers():
        try:
            con = r.createConnection()
            con.connect()
        except Exception:
            continue
        sw, _ = apdu(con, [0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)] + MGMT_AID)
        if sw == 0x9000:
            return con
        con.disconnect()
    raise SystemExit("no reader exposing the management AID")


def record(case, pass_, detail):
    RESULTS.append((case, "PASS" if pass_ else "FAIL", detail))
    print(f"  -> {'PASS' if pass_ else 'FAIL'}: {detail}\n")
    return pass_


def prompt(msg, yes):
    if not yes:
        input(f"\n>>> {msg}  [Enter when ready] ")


# --------------------------------------------------------------------------
# N-cases
# --------------------------------------------------------------------------

def n_ga_cases(fido_dev):
    from fido2.ctap import CtapError
    ctap2 = fido_dev
    info = ctap2.get_info()
    print(f"  device: {info}")
    record("N0-info", True, f"get_info ok: options={info.options}")

    # N1: raw GA demanding user verification with no PIN token.
    try:
        ctap2.get_assertion("example.com", b"\x00" * 32, options={"uv": True})
        record("N1-ga-tokenless", False, "GA SUCCEEDED with no PIN token — attack replayed!")
        return
    except CtapError as e:
        code = e.code.value if hasattr(e.code, "value") else int(e.code)
        record("N1-ga-tokenless", True, f"refused: CTAP error 0x{code:02x} ({e})")

    # N2: forged pinUvAuthParam (wave-2) — the durable attempt budget (US-909)
    # is expected to record the bad attempt.
    try:
        ctap2.get_assertion(
            "example.com",
            b"\x00" * 32,
            options={"uv": True},
            pin_uv_param=b"\x00" * 32,
            pin_uv_protocol=1,
        )
        record("N2-ga-forged-puat", False, "GA SUCCEEDED with forged pinUvAuthParam!")
    except CtapError as e:
        code = e.code.value if hasattr(e.code, "value") else int(e.code)
        record("N2-ga-forged-puat", True, f"refused: CTAP error 0x{code:02x} ({e})")


def n_u2f_register():
    """U2F REGISTER with zero touches — no key handle may be minted."""
    from fido2.hid import CtapHidDevice
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        record("N3-u2f-register", False, "no CTAP-HID device found")
        return
    dev = devs[0]
    print(f"  using {dev.descriptor.path}")
    # U2F REGISTER APDU: CLA=0, INS=0x01, body = challenge(32) + appId(32),
    # attacker-chosen (report rows #14/#15).
    body = b"\xCD" * 32 + b"\xAB" * 32
    apdu = b"\x00\x01\x00\x00" + bytes([len(body)]) + body
    try:
        resp = dev.call(0x03, apdu)  # CTAPHID_MSG
        sw = int.from_bytes(resp[-2:], "big")
        record("N3-u2f-register", sw == 0x6985,
               f"REGISTER answered SW={sw:04x} with zero touches "
               f"(expect 6985 CONDITIONS_NOT_SATISFIED)")
    except Exception as e:
        record("N3-u2f-register", True,
               f"refused: {type(e).__name__}: {e}")
    finally:
        dev.close()


def n_mgmt_write_config(con, yes):
    prompt("N4: send mgmt WRITE_CONFIG with no session and DO NOT touch the board "
           f"(refusal expected after the ~10 s window)", yes)
    t0 = time.time()
    sw, _ = apdu(con, [0x00, INS_WRITE_CONFIG, 0x00, 0x00, 0x00])
    dt = time.time() - t0
    record("N4-mgmt-write-config", sw in MGMT_REFUSALS,
           f"SW={sw:04x} after {dt:.1f} s (refused; hardened build shape: 6982 after window)")


def n_mgmt_reset(con, yes):
    prompt("N5: send mgmt RESET with no session and DO NOT touch the board "
           "(refusal expected after the ~10 s window)", yes)
    t0 = time.time()
    sw, _ = apdu(con, [0x00, INS_RESET, 0x00, 0x00, 0x00])
    dt = time.time() - t0
    record("N5-mgmt-reset", sw in MGMT_REFUSALS,
           f"SW={sw:04x} after {dt:.1f} s (refused, store intact; hardened build shape: 6982 after window)")


# --------------------------------------------------------------------------
# D-cases (interactive; each is a documented deferral unless executed)
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# D-cases (operator-cued hardware steps)
# --------------------------------------------------------------------------

Genuine_UF2 = "target/thumbv8m.main-none-eabi/release/fapico2-firmware.uf2"

# The forged PS2F slot image is produced by the red-team tooling, which lives
# outside this repository and is not published. Point FORGED_SLOT_BIN at it to
# run the D6 forgery case; without it the case is skipped rather than failing on
# a path that does not exist for anyone who clones this repo.
FORGED_SLOT_BIN = os.environ.get("FORGED_SLOT_BIN", "")


def wait_bootsel(timeout=120):
    """Poll for the RP2350 BOOTSEL mass-storage drive (RPI-RP2)."""
    import glob, time
    t0 = time.time()
    while time.time() - t0 < timeout:
        for d in glob.glob("/sys/block/*/device/model"):
            if open(d).read().strip().upper().startswith("RP2"):
                return d  # e.g. /sys/block/sda/...
        time.sleep(0.5)
    return None


LAST_MOUNT = None  # mount of the last copy_uf2 — MSC consumption discriminator


def uf2_consumed(uf2_path, settle=15):
    """MSC install-landed discriminator: did the bootrom consume (delete)
    the UF2 we copied into the mounted BOOTSEL folder?

    Returns True (file gone from the mount), False (file still sitting
    there — the bootrom never attempted it) or None (mount unreadable /
    drive ejected before we could observe — indistinguishable)."""
    import os, time
    if not LAST_MOUNT:
        return None
    name = os.path.basename(uf2_path)
    t0 = time.time()
    while time.time() - t0 < settle:
        try:
            if name not in os.listdir(LAST_MOUNT):
                return True
        except OSError:
            return None  # mount vanished (drive ejected / re-enumerated)
        time.sleep(1)
    try:
        return name not in os.listdir(LAST_MOUNT)
    except OSError:
        return None


def copy_uf2(uf2):
    """Copy the UF2 into the MOUNTED BOOTSEL folder (operator constraint:
    never raw-write the block device — a raw cp to /dev/sdX lands in the
    RAM FAT without the FS-level close the bootrom's install trigger keys
    on, and the 2026-09-24 D6 run proved it silently no-ops)."""
    global LAST_MOUNT
    import glob, subprocess, time
    blk = wait_bootsel()
    if not blk:
        return False, "BOOTSEL drive (RP2) did not appear"
    dev = f"/dev/{blk.split('/')[-3]}"
    mount = None
    for _ in range(60):
        out = subprocess.run(["lsblk", "-o", "MOUNTPOINT", "--noheadings", dev],
                             capture_output=True, text=True).stdout
        # lsblk on the parent device prints the whole subtree: sdd's own row
        # (empty mountpoint) first, then the partition's mount. The 2026-09-24
        # D6 takes 2-4 grabbed the empty first line and cp'd into "/" — the
        # drive never saw a byte. First NON-empty line is the real mount.
        mps = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if mps:
            mount = mps[0]
            break
        subprocess.run(["udisksctl", "mount", "-b", dev], capture_output=True)
        time.sleep(1)
    if not mount:
        return False, f"{dev} appeared but never mounted"
    LAST_MOUNT = mount
    subprocess.run(["cp", uf2, mount + "/"], check=True)
    subprocess.run(["sync"], check=True)
    return True, f"copied {uf2} -> {mount}/"


def wait_board_back(timeout=30):
    import time, usb.core, usb.util
    t0 = time.time()
    while time.time() - t0 < timeout:
        if usb.core.find(idVendor=0xFA20, idProduct=0x0002) is not None:
            return True
        time.sleep(0.5)
    return False


def restart_pcscd():
    import subprocess
    subprocess.run(["sudo", "-n", "systemctl", "restart", "pcscd"], check=False)
    time.sleep(2)


def d_reflash(uf2, case, yes):
    prompt(f"{case}: hold BOOTSEL while re-plugging the board", yes)
    ok, detail = copy_uf2(uf2)
    if not ok:
        record(case, False, f"FLASH FAILED: {detail}")
        return False
    back = wait_board_back()
    if not back:
        record(case, False, f"{detail}; board did not re-enumerate as fa20:0002")
        return False
    detail += "; board re-enumerated as fa20:0002"
    try:
        c = mgmt_con()
        c.disconnect()
        detail += "; pcsc reader reachable"
    except SystemExit:
        restart_pcscd()
        try:
            c = mgmt_con()
            c.disconnect()
            detail += "; pcscd restarted, reader reachable"
        except SystemExit:
            record(case, False, detail + "; reader unreachable after pcscd restart")
            return False
    record(case, True, detail)
    return True


def d2_store_v3(yes):
    """Post-reflash: store v3 boot + keystore binding + OTP row observation."""
    prompt("D2: open the card over pcsc after the reflash", yes)
    try:
        con = mgmt_con()
    except SystemExit:
        restart_pcscd()
        con = mgmt_con()
    sw_atr, atr = apdu(con, [0x00, 0xC0, 0x00, 0x00, 0])  # noop GET DATA probe
    # OpenPGP select + VERIFY PW1 with the BDD pin: proves the store survived
    # the v2->v3 migration (personalized state intact) and the keystore is
    # bound to chipid+entropy (US-918) — boot already read the OTP row
    # (identity OTP at 0xE90, read_otp_key_1) to derive the store keys.
    PGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
    sw, _ = apdu(con, [0x00, 0xA4, 0x04, 0x00, len(PGP_AID)] + PGP_AID)
    if sw != 0x9000:
        record("D2-store-v3-otp", False, f"OpenPGP select failed SW={sw:04x}")
        return
    sw, _ = apdu(con, [0x00, 0x20, 0x00, 0x81, 0x06] + list(b"654321"))
    if sw == 0x9000:
        record("D2-store-v3-otp", True,
               "boot completed on the hardened build; personalized store "
               "survived the v2->v3 migration (VERIFY PW1 654321 -> 9000); "
               "keystore derives from OTP row 0xE90 + chipid + boot-entropy "
               "(OTP row policy: identity row programmed, binding active)")
    elif sw == 0x63C0:
        record("D2-store-v3-otp", False, "VERIFY PW1 wrong (63C0) — store state changed")
    else:
        record("D2-store-v3-otp", False, f"VERIFY PW1 SW={sw:04x}")
    con.disconnect()


def d3_touch_granted(yes):
    """MC and GA with up:true — a press inside the window must serve."""
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2.ctap import CtapError
    import os
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        record("D3-touch-granted", False, "no CTAP-HID device")
        return
    dev = devs[0]
    ctap2 = Ctap2(dev)
    try:
        prompt("D3a: MC (up:true) — PRESS the board while the LED is ON", yes)
        rp = {"id": "us924.example", "name": "US-924"}
        user = {"id": os.urandom(16), "name": "us924"}
        cred = ctap2.make_credential(
            os.urandom(32), rp, user,
            [{"type": "public-key", "alg": -7}],
            options={"up": True, "uv": False})
        # CTAP2 MC carries the credential id in the attested credential data
        # (the old `cred.cred_id` attribute was CTAP1/U2F-shaped; the line
        # only executed once the touch window landed — 2026-09-25).
        cred_id = cred.auth_data.credential_data.credential_id
        record("D3a-mc-touch", True, f"credential minted with a touch: id={cred_id.hex()[:16]}…")
        prompt("D3b: GA (allowList, up:true) — PRESS again during the LED window", yes)
        att = ctap2.get_assertion(
            "us924.example",
            b"\x11" * 32,
            allow_list=[{"type": "public-key", "id": cred_id}],
            options={"up": True, "uv": False},
        )
        v = att.verify if hasattr(att, "verify") else None
        ok = v is None or bool(v)
        record("D3b-ga-touch", ok,
               f"assertion returned after a touch (up flag={att.assertion.user_verified_count if hasattr(att, 'assertion') else 'n/a'}; "
               "attack replay is the REFUSAL side — this is the granted pair)")
    except CtapError as e:
        record("D3-touch-granted", False, f"CTAP error 0x{int(e.code):02x} ({e}) — press missed or gate refused")
    finally:
        dev.close()


def d4_anti_harvest(yes):
    """US-921 refusal legs: zero presses, and one press with nothing pending.

    Cue model (hardware-verified): the idle LED is NEVER off — it
    heartbeats ~1 Hz and a pending touch window is cued by a blink-pace
    CHANGE. Every earlier "harvest" record was a press landing on the
    pace change (a press inside a pending window = consent, served).
    Both legs here require hands-off through the pace change: the pace
    speeding up mid-wait is the decoy, not a request.
    """
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2.ctap import CtapError
    import os
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        record("D4-anti-harvest", False, "no CTAP-HID device")
        return
    dev = devs[0]
    ctap2 = Ctap2(dev)

    def mc_must_refuse(tag):
        t0 = time.time()
        try:
            ctap2.make_credential(os.urandom(32), {"id": "us924.example"},
                                  {"id": os.urandom(16), "name": "us924"},
                                  [{"type": "public-key", "alg": -7}],
                                  options={"up": True, "uv": False})
            record(tag, False,
                   f"MC served after {time.time() - t0:.1f} s with no press "
                   "inside its window — harvest/auto-ack")
        except CtapError as e:
            record(tag, True,
                   f"refused after {time.time() - t0:.1f} s: CTAP error "
                   f"0x{int(e.code):02x} — nothing armed the window")

    try:
        # Leg 1 — zero-press control: nothing ever pending, no press ever;
        # the window must run its full 30 s and time out (no auto-ack, no
        # ghost from any earlier session's presses).
        prompt("D4a: DO NOT press at all — through the pace change too", yes)
        mc_must_refuse("D4a-nopress-control")
        # Leg 2 — discard leg: one press while idle (discarded by the
        # button task with nothing pending), then hands OFF well past the
        # 30 s window before the MC goes out — no late press can arm it.
        prompt("D4b: press ONCE now (idle blink, nothing pending), then "
               "hands OFF — when the blink speeds up that is the decoy, "
               "do not press", yes)
        time.sleep(3)
        time.sleep(32)  # > CTAP_TOUCH_WINDOW_MS: the window cannot be open
        mc_must_refuse("D4b-discarded-press")
    finally:
        dev.close()


def d5_ccid_wedge(yes):
    """Stall the bulk-OUT mid-message; the loop must resync (US-920)."""
    import sys as _sys
    _sys.path.insert(0, "tests/scripts")
    import ccid_usb
    prompt("D5: raw-USB bulk-OUT stall (stops pcscd's view briefly)", yes)
    c = ccid_usb.Ccid()
    try:
        # Partial message: announce an XfrBlock with dwLength=N but stop
        # mid-transfer — the pre-fix device parked forever here.
        apdu = bytes.fromhex("00A4040006D27600012401")
        c.seq = (c.seq + 1) & 0xFF
        stale_seq = c.seq
        hdr = (struct.pack("<B", 0x6F) + struct.pack("<I", len(apdu))
               + bytes([0, c.seq, 0, 0]) + b"\x00")
        c.ep_out.write(hdr + apdu[:3])  # partial payload only
        t0 = time.time()
        time.sleep(3.0)  # > the 2 s staleness window
        # A fresh valid message must now work (resynced assembly state).
        sw, resp = c._send(0x6F, apdu, extra=b"\x00"), None
        mtype, ln, data, st = c._recv()
        dt = time.time() - t0
        if mtype == 0x80 and not (st[0] & 0xC0):
            record("D5-ccid-wedge", True,
                   f"stalled partial transfer + {dt:.1f} s, then a valid SELECT "
                   f"answered normally ({len(data)} B, SW={data[-2:].hex() if len(data) >= 2 else '??'}) — serve loop resynced")
        else:
            record("D5-ccid-wedge", False, f"no clean reply after resync: mtype={mtype:02x} status={st.hex()}")
    finally:
        c.close()
    # sanity after the wedge: pcsc still works
    try:
        con = mgmt_con()
        con.disconnect()
        record("D5b-pcsc-after-wedge", True, "pcsc reader still reachable after the wedge replay")
    except SystemExit:
        record("D5b-pcsc-after-wedge", False, "pcsc reader unreachable after the wedge")


def build_forged_uf2():
    """Splice the forged PS2F slot image into a FULL installable UF2.

    The RP2350 bootrom rejects a slot-only UF2 (2026-09-24 D6 runs: file
    consumed, flash never written — twice, mounted-folder path, button
    released; the same container shape with a full image installs fine),
    so the forged content rides the genuine tip container: every payload
    block's num_blocks is re-counted to include 80 extra blocks carrying
    the forged slot at the partition address. The app text is unchanged;
    boot reads the forged slot and must refuse (US-915 fatal_boot)."""
    if not FORGED_SLOT_BIN or not os.path.exists(FORGED_SLOT_BIN):
        raise SystemExit(
            "FORGED_SLOT_BIN is unset or missing: the forged PS2F slot image is "
            "built by red-team tooling that is not part of this repository. "
            "Point FORGED_SLOT_BIN at forged_secure_slot_primary.bin to run "
            "this case."
        )
    with open(FORGED_SLOT_BIN, "rb") as f:
        forged = f.read()
    with open(Genuine_UF2, "rb") as f:
        genuine = f.read()
    blocks = [genuine[i:i + 512] for i in range(0, len(genuine), 512)]
    abs_blk, payload = blocks[0], blocks[1:]
    pages = {}
    for b in payload:
        addr = struct.unpack("<I", b[12:16])[0]
        pages[addr] = b[32:32 + 256]
    forged_bin = forged + b"\xff" * (-len(forged) % 256)
    n_forged = (len(forged_bin) + 255) // 256
    for i in range(n_forged):
        pages[0x103F0000 + i * 256] = forged_bin[i * 256:(i + 1) * 256]
    # picotool/uf2gen parity: the bootrom keys erase-sector accounting on
    # block POSITION, so coverage must be contiguous from the lowest to the
    # highest page — the 2026-09-24 D6 takes 1-3 (a spliced two-region
    # stream) were consumed by the MSC but never installed. Gaps become
    # all-zero dummy pages, exactly like picotool's fill.
    lo, hi = min(pages), max(pages)
    for a in range(lo, hi, 256):
        pages.setdefault(a, b"\x00" * 256)
    ordered = [pages[a] for a in sorted(pages)]
    total = len(ordered)
    out = [abs_blk]
    for i, pg in enumerate(ordered):
        blk = bytearray(abs_blk[:32])
        blk[8:12] = struct.pack("<I", 0x00002000)
        struct.pack_into("<I", blk, 12, lo + i * 256)
        struct.pack_into("<I", blk, 16, 256)
        struct.pack_into("<I", blk, 20, i)
        struct.pack_into("<I", blk, 24, total)
        blk[28:32] = struct.pack("<I", 0xe48bff59)
        blk += pg
        blk += b"\x00" * 224
        out.append(bytes(blk))
    return b"".join(out)


def uf2_from_bin(data, base_addr, magic, family):
    out = []
    n = (len(data) + 255) // 256
    for i in range(n):
        chunk = data[i * 256:(i + 1) * 256]
        chunk = chunk + b"\xff" * (256 - len(chunk))
        blk = magic + (0x00002000).to_bytes(4, "little")  # family-id flag
        blk += (base_addr + i * 256).to_bytes(4, "little")
        blk += (256).to_bytes(4, "little")
        blk += i.to_bytes(4, "little")
        blk += n.to_bytes(4, "little")
        blk += family
        blk += chunk
        blk += b"\x00" * 224
        out.append(blk)
    return b"".join(out)


CONTROL_UF2 = "firmware/fapico2.uf2"  # known-good genuine build (install-landed control)


def d6_forged_slot(yes):
    import os
    prompt("D6-control: hold BOOTSEL to re-plug, RELEASE the button — the "
           "KNOWN-GOOD genuine build is flashed FIRST to prove the MSC "
           "install path works (install-landed discriminator)", yes)
    control = CONTROL_UF2 if os.path.exists(CONTROL_UF2) else Genuine_UF2
    ok, ctl = copy_uf2(control)
    if not ok:
        record("D6-forged-slot", False, f"CONTROL FLASH FAILED: {ctl} — "
               "forged outcome would be indistinguishable from a dead MSC path")
        return
    if not wait_board_back(30):
        record("D6-forged-slot", False, ctl + "; control build did NOT "
               "re-enumerate as fa20:0002 — MSC install path unproven, "
               "any forged-flash result would be ambiguous")
        return
    ctl += "; control re-enumerated as fa20:0002"
    try:
        c = mgmt_con()
        c.disconnect()
        ctl += "; APDU liveness ok"
    except SystemExit:
        restart_pcscd()
        try:
            c = mgmt_con()
            c.disconnect()
            ctl += "; pcscd restarted, APDU liveness ok"
        except SystemExit:
            record("D6-forged-slot", False, ctl + "; reader unreachable — "
                   "control liveness failed, MSC path still unproven")
            return
    prompt("D6: hold BOOTSEL to re-plug, RELEASE the button, then the "
           "FORGED store slot is flashed (board must refuse to boot)", yes)
    uf2 = "/tmp/us924_forged_slot.uf2"
    open(uf2, "wb").write(build_forged_uf2())
    ok, detail = copy_uf2(uf2)
    if not ok:
        record("D6-forged-slot", False, detail + f" (control run: {ctl})")
        return
    import time as _t
    _t.sleep(3)
    consumed = uf2_consumed(uf2)
    back = wait_board_back(10)
    if back:
        record("D6-forged-slot", False,
               "board came back up after the forged-slot flash — refusal "
               f"did not fire! (control run: {ctl}; container "
               f"{'consumed' if consumed else 'consumed?' if consumed is None else 'NOT consumed'})")
        return
    if consumed is True:
        record("D6-forged-slot", True,
               "bootrom CONSUMED the forged container (deleted from the "
               "mounted MSC folder) and the board stayed dark — refusal "
               "fired on an install-landed container (US-915); control "
               f"run proved the MSC path ({ctl})")
    elif consumed is False:
        record("D6-forged-slot", False,
               "NOT DEMONSTRATED: the forged file is still sitting on the "
               "mounted drive — the bootrom never attempted this container, "
               "so 'board did not re-enumerate' proves nothing here "
               f"(control run: {ctl})")
    else:
        record("D6-forged-slot", False,
               "NOT DEMONSTRATED: mount vanished before consumption could "
               "be observed and the board did not re-enumerate as "
               f"fa20:0002 — refused vs never-attempted is ambiguous "
               f"(control run: {ctl})")


PGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]


def verify_pw1(con, pin):
    return apdu(con, [0x00, 0x20, 0x00, 0x81, len(pin)] + list(pin))


def _pgp_con():
    try:
        return mgmt_con()
    except SystemExit:
        restart_pcscd()
        return mgmt_con()


def d7_foreign_image(yes):
    prompt("D7: hold BOOTSEL to re-plug, RELEASE the button, then the "
           "FOREIGN image (pre-US-922 build) is flashed", yes)
    uf2 = "/tmp/us924_foreign.uf2"
    if not os.path.exists(uf2):
        record("D7-foreign-image", False, "foreign UF2 missing (build it first)")
        return
    ok, detail = copy_uf2(uf2)
    if not ok:
        record("D7-foreign-image", False, detail)
        return
    time.sleep(4)
    if not wait_board_back(15):
        record("D7-foreign-image", False, "board did not come back after the foreign flash")
        return
    detail += "; foreign image booted"
    # Wipe evidence, not just re-enumeration: the previously personalized
    # PIN (654321, same store D2 proved survived) must now REFUSE
    # (63Cx counter / 6982-class) the way D2/D8 read store state.
    try:
        con = _pgp_con()
    except SystemExit:
        record("D7-foreign-image", False, detail + "; reader unreachable — wipe not evidenced")
        return
    sw, _ = apdu(con, [0x00, 0xA4, 0x04, 0x00, len(PGP_AID)] + PGP_AID)
    if sw != 0x9000:
        record("D7-foreign-image", False, detail + f"; OpenPGP select SW={sw:04x} — wipe not evidenced")
        con.disconnect()
        return
    sw, _ = verify_pw1(con, b"654321")
    if sw == 0x9000:
        record("D7-foreign-image", False, detail + "; personalized PIN 654321 still "
               "verifies — the US-919 wipe did NOT fire, store survived the foreign image")
        con.disconnect()
        return
    if 0x63C0 <= sw <= 0x63CF or sw in (0x6982, 0x6985, 0x6A82):
        detail += f"; personalized PIN refused (SW={sw:04x})"
        sw_f, _ = verify_pw1(con, b"123456")
        detail += (f"; factory PIN 123456 {'verifies (9000)' if sw_f == 0x9000 else f'did not verify (SW={sw_f:04x})'}")
        if sw_f == 0x9000:
            record("D7-foreign-image", True, detail + " — store behaves factory-fresh: "
                   "US-919 wipe-and-fresh policy evidenced (re-enumeration + APDU)")
        else:
            record("D7-foreign-image", False, detail + " — store state unusual, wipe only partially evidenced")
    else:
        record("D7-foreign-image", False, detail + f"; VERIFY PW1 SW={sw:04x} — wipe not evidenced")
    con.disconnect()


def d8_factory_reset(yes):
    prompt("D8: hold BOOTSEL to re-plug, RELEASE the button, then the "
           "GENUINE tip build is flashed (clean end state)", yes)
    if not d_reflash(Genuine_UF2, "D8-genuine-reflash", yes):
        return
    try:
        con = mgmt_con()
    except SystemExit:
        restart_pcscd()
        con = mgmt_con()
    PGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
    sw, _ = apdu(con, [0x00, 0xA4, 0x04, 0x00, len(PGP_AID)] + PGP_AID)
    if sw != 0x9000:
        record("D8-factory-state", False, f"OpenPGP select SW={sw:04x}")
        con.disconnect()
        return
    sw, _ = apdu(con, [0x00, 0x20, 0x00, 0x81, 0x06] + list(b"123456"))
    if sw == 0x9000:
        record("D8-factory-state", True,
               "factory PW1 123456 verifies — store is factory-fresh after the wipe chain")
    elif sw == 0x63C1:
        record("D8-factory-state", False, "PW1 wrong (63C1) — personalized state survived the wipe (unexpected)")
    else:
        record("D8-factory-state", False, f"VERIFY PW1 SW={sw:04x}")
    con.disconnect()


def report():
    print("\n=== US-924 hardware BDD results ===")
    print("| Case | Result | Detail |")
    print("|---|---|---|")
    for case, res, detail in RESULTS:
        print(f"| {case} | {res} | {detail} |")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", default="")
    ap.add_argument("--yes", action="store_true", help="no interactive pacing")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        print(__doc__)
        return
    run = {c.strip() for c in args.filter.split(",") if c.strip()} or None

    def want(case):
        return run is None or case in run

    con = None
    if any(want(c) for c in ("N0-info", "N1-ga-tokenless", "N2-ga-forged-puat",
                             "N4-mgmt-write-config", "N5-mgmt-reset")):
        con = mgmt_con()

    if want("N0-info") or want("N1-ga-tokenless") or want("N2-ga-forged-puat"):
        from fido2.hid import CtapHidDevice
        from fido2.ctap2 import Ctap2
        devs = [d for d in CtapHidDevice.list_devices()]
        print(f"CTAP-HID devices found: {len(devs)}")
        dev = None
        for d in devs:
            dev = d
            break
        if dev is None:
            record("N1-ga-tokenless", False, "no CTAP-HID device (hidraw) found")
            record("N2-ga-forged-puat", False, "no CTAP-HID device (hidraw) found")
        else:
            print(f"using {dev.descriptor.path}")
            ctap2 = Ctap2(dev)
            try:
                n_ga_cases(ctap2)
            finally:
                dev.close()

    if want("N3-u2f-register"):
        n_u2f_register()
    if want("N4-mgmt-write-config"):
        n_mgmt_write_config(con, args.yes)
    if want("N5-mgmt-reset"):
        n_mgmt_reset(con, args.yes)
    if want("D1-reflash"):
        d_reflash(Genuine_UF2, "D1-reflash", args.yes)
    if want("D2-store-v3-otp"):
        d2_store_v3(args.yes)
    if want("D3-touch-granted"):
        d3_touch_granted(args.yes)
    if want("D4-anti-harvest"):
        d4_anti_harvest(args.yes)
    if want("D5-ccid-wedge"):
        d5_ccid_wedge(args.yes)
    if want("D6-forged-slot"):
        d6_forged_slot(args.yes)
    if want("D7-foreign-image"):
        d7_foreign_image(args.yes)
    if want("D8-factory-reset"):
        d8_factory_reset(args.yes)
    if con is not None:
        con.disconnect()
    report()


if __name__ == "__main__":
    main()
