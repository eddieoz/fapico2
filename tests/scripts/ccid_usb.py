#!/usr/bin/env python3
"""Minimal CCID-over-USB raw APDU client for the fapico2 board (pyusb).

Copied verbatim from the proven P7-C7 helper (/tmp/p7c7/ccid_usb.py, sha
verified identical at copy time) with one local change for the S-731-1
mixed FIDO(HID)+CCID workflow (documented deviation): the kernel-driver
detach is scoped to the CCID interface only (the original detached both
interfaces, which killed the board's FIDO hidraw node), and close()
re-attaches the detached kernel driver.
"""
import struct
import sys
import usb.core
import usb.util

VID, PID = 0xFA20, 0x0002

def find_dev():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise SystemExit("fapico2 (fa20:0002) not found")
    try:
        dev.set_configuration()
    except usb.core.USBError as e:
        if "busy" not in str(e):
            raise
    cfg = dev.get_active_configuration()
    ccid_intf = usb.util.find_descriptor(cfg, bInterfaceClass=0x0B)
    if ccid_intf is None:
        ccid_intf = cfg[(0, 0)]
    # local change: detach the kernel driver on the CCID interface ONLY
    # (the proven helper detached both, nuking the FIDO hidraw node)
    try:
        if dev.is_kernel_driver_active(ccid_intf.bInterfaceNumber):
            dev.detach_kernel_driver(ccid_intf.bInterfaceNumber)
    except (AttributeError, usb.core.USBError):
        pass
    intf = ccid_intf
    ep_out = ep_in = None
    for ep in intf:
        if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT:
            ep_out = ep
        else:
            ep_in = ep
    return dev, intf, ep_out, ep_in

class Ccid:
    def __init__(self):
        self.dev, self.intf, self.ep_out, self.ep_in = find_dev()
        self.seq = 0
        # drain stale bulk-IN responses from earlier aborted sessions
        try:
            while True:
                self.ep_in.read(512, timeout=300)
        except Exception:
            pass
    def _send(self, msg_type, payload=b"", extra=b"\x00"):
        self.seq = (self.seq + 1) & 0xFF
        self._last_seq = self.seq
        # common header: msg(1) len(4 LE) slot(1) seq(1) RFU(2); then the
        # type-specific byte (bVoltageClass for PowerOn, bRFU for XfrBlock)
        hdr = (struct.pack("<B", msg_type) + struct.pack("<I", len(payload))
               + bytes([0, self.seq, 0, 0]) + extra)
        self.ep_out.write(hdr + payload)
    def _recv(self):
        while True:
            data = bytes(self.ep_in.read(512, timeout=5000))
            seq = data[6]
            if seq != self._last_seq:
                continue  # stale response for an earlier request
            mtype = data[0]
            ln = struct.unpack("<I", data[1:5])[0]
            status = data[7:9]
            return mtype, ln, bytes(data[10:10+ln]), status
    def power_on(self):
        self._send(0x62, extra=b"\x00")  # IccPowerOn, auto voltage
        mtype, ln, atr, st = self._recv()
        if mtype != 0x80:
            raise RuntimeError("power_on: mtype %02X" % mtype)
        return atr
    def transmit(self, apdu):
        self._send(0x6F, bytes(apdu), extra=b"\x00")  # XfrBlock
        mtype, ln, resp, st = self._recv()
        if mtype != 0x80:
            raise RuntimeError("xfr: mtype %02X" % mtype)
        if st[0] & 0xC0:
            raise RuntimeError("xfr: CCID status %02X error %02X" % (st[0], st[1]))
        return resp
    def close(self):
        # local change: re-attach the kernel driver we detached (iface-local)
        try:
            if not self.dev.is_kernel_driver_active(self.intf.bInterfaceNumber):
                self.dev.attach_kernel_driver(self.intf.bInterfaceNumber)
        except (AttributeError, usb.core.USBError):
            pass
        usb.util.dispose_resources(self.dev)

if __name__ == "__main__":
    c = Ccid()
    print("ATR:", c.power_on().hex(" "))
    r = c.transmit(bytes.fromhex("00A4040006D27600012401"))
    print("SELECT:", r.hex(" "))
    r = c.transmit(bytes.fromhex("00CA00C1FE"))
    print("C1:", r.hex(" "))
    c.close()
