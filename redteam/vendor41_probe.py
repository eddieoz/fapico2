"""vendor41 (RS-Key) channel — correct framing.

The RS-Key vendor channel is the CTAP2 *opcode* 0x41 inside a standard
CTAPHID_CBOR frame (frame cmd 0x90): payload = 0x41 || CBOR-map. Response is
a status byte followed by a CBOR map on success.

Authority per apps/fido/src/vendor41.rs `decision()`:
  MSE 0x01 Ungated      | EXPORT 0x02 Touch     | LOAD 0x03 Touch
  FINALIZE 0x04 Touch   | STATE 0x05 StatusOnly | UNLOCK 0x06 Touch
  AUDIT_READ 0x07 StatusOnly | AUDIT_CHECKPOINT 0x08 Touch
  ATT_IMPORT 0x09 Touch | ATT_CLEAR 0x0A Touch  | ATT_STATE 0x0B StatusOnly
  CONFIG_WRITE 0x0C Touch | CONFIG_READ 0x0D Ungated | AUDIT_CONFIG 0x0E StatusOnly
"""
import sys, time
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from ctaphid import CTAPHID
import cbor2

h = CTAPHID()
h.init()
cid = h.cid
print("cid=%08x" % cid)

def op(name, sub, body=None, timeout=6.0):
    """sub as CBOR key 1; body as the params map (or None)."""
    m = {1: sub}
    if body is not None:
        m[2] = body
    payload = bytes([0x41]) + cbor2.dumps(m)
    try:
        r = h.cbor(cid, payload, timeout)
        st = r[0]
        raw = r[1:]
        if st == 0:
            try:
                dec = cbor2.loads(raw)
                extra = " map=%s" % dec
            except Exception:
                extra = " raw=%s" % raw.hex()[:60]
        else:
            extra = ""
        print("  %-22s sub %02X -> status=%02x%s" % (name, sub, st, extra))
        return st, raw
    except Exception as e:
        print("  %-22s sub %02X -> EXC %s" % (name, sub, str(e)[:50]))
        return None, None

print("\n--- tokenless sub-commands (what they claim to allow) ---")
op("MSE (ungated)",     0x01)
op("STATE (statusonly)", 0x05)
op("AUDIT_READ",        0x07)
op("ATT_STATE",         0x0B)
op("CONFIG_READ",       0x0D, {1: 0x01})   # target PHY
op("CONFIG_READ LED",   0x0D, {1: 0x02})   # target LED
op("AUDIT_CONFIG",      0x0E)

print("\n--- token-gated sub-commands unauthenticated (expect refusal) ---")
op("EXPORT",   0x02)
op("LOAD",     0x03)
op("FINALIZE", 0x04)
op("UNLOCK",   0x06)
op("AUDIT_CHECKPOINT", 0x08)
op("ATT_IMPORT", 0x09)
op("ATT_CLEAR",  0x0A)
op("CONFIG_WRITE", 0x0C, {1: 0x01, 2: b"\x00" * 8})

print("\n--- malformed / undefined sub-commands ---")
for sub in (0x00, 0x0F, 0x10, 0x7F, 0xFF):
    op("undefined %02X" % sub, sub)

h.close()