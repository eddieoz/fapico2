"""CTAPHID transport-layer fuzzing: INIT/CID flood, framing abuse, CBOR parser
hostility, largeBlobs, and the vendor 0x41 channel. Success = the device
survives every input with a defined response (no hang, no drop-off).
"""
import sys, os, struct, time, select, random
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from ctaphid import CTAPHID
import cbor2

DEV = "/dev/hidraw8"

def raw_write(frame):
    fd = os.open(DEV, os.O_RDWR | os.O_NONBLOCK)
    try:
        os.write(fd, b"\x00" + frame.ljust(64, b"\x00")[:64])
    except OSError as e:
        return str(e)
    finally:
        os.close(fd)

def raw_read(timeout=0.4):
    fd = os.open(DEV, os.O_RDWR | os.O_NONBLOCK)
    try:
        r, _, _ = select.select([fd], [], [], timeout)
        if r:
            return os.read(fd, 65).hex()[:40]
    except OSError:
        pass
    finally:
        os.close(fd)
    return None

def frame(cid, cmd, data=b""):
    return struct.pack(">IBH", cid, cmd, len(data)) + data

def alive():
    try:
        h = CTAPHID(DEV); h.init()
        r = h.ping(h.cid, b"ALIVE")
        h.close()
        return r == b"ALIVE"
    except Exception:
        return False

print("=== baseline alive:", alive())

# --- 1. INIT flood: 60 rapid INITs on broadcast, watch CID allocation ----
h = CTAPHID(DEV)
cids = []
for i in range(60):
    _, _, p = h.init(b"\x00" * 8)
    cids.append(struct.unpack(">I", p[8:12])[0])
h.close()
print("INIT x60: unique CIDs=%d first=%08x last=%08x monotonic=%s"
      % (len(set(cids)), cids[0], cids[-1], cids == sorted(cids)))
print("alive after INIT flood:", alive())

# --- 2. PING with max and oversized payloads ----------------------------
for n in (0, 1, 7608, 7609, 7610, 65535):
    raw_write(frame(0xFFFFFFFF, 0x86, b"\x00" * 8))  # get a fresh cid
    resp = raw_read()
    if not resp:
        print("PING len %-6d: no cid" % n); continue
    cid = bytes.fromhex(resp)[15:19]
    # build a correctly-sequenced oversized frame set
    data = b"A" * n
    first = frame(struct.unpack(">I", cid)[0], 0x81, data[:57])
    raw_write(first)
    # continuation frames
    off = 57
    seq = 0
    while off < n and seq < 5:
        chunk = data[off:off+59]
        raw_write(struct.pack(">IB", struct.unpack(">I", cid)[0], 0x80 | seq) + chunk)
        off += len(chunk); seq += 1
    time.sleep(0.05)
    print("PING len %-6d -> %s" % (n, raw_read(0.5)))

print("alive after size abuse:", alive())

# --- 3. Framing abuse: bad seq, stray continuations, unknown cmds --------
cid = 0x00001234
bad = [
    ("seq out of order",        frame(cid, 0x81, b"X" * 10)),
    ("stray continuation",      struct.pack(">IB", cid, 0x81) + b"junk"),
    ("reserved CID 0",          frame(0x00000000, 0x81, b"X" * 8)),
    ("bridge CID [0,0,0,1]",    frame(0x00000001, 0x81, b"X" * 8)),
    ("unknown init cmd 0x7F",   frame(cid, 0xFF, b"X" * 8)),
    ("BCNT > CTAPHID_MAX",      frame(cid, 0x81, b"X" * 8)[:-2] + struct.pack(">H", 0xFFFF)),
]
for name, f in bad:
    raw_write(f)
    print("%-24s -> %s" % (name, raw_read(0.5)))
print("alive after framing abuse:", alive())

# --- 4. CBOR parser hostility on a live CID -----------------------------
h = CTAPHID(DEV); h.init(); cid = h.cid
def cbor_raw(name, payload, timeout=2.0):
    try:
        r = h.cbor(cid, payload, timeout)
        print("%-34s status=%02x len=%d" % (name, r[0], len(r) - 1))
        return r
    except Exception as e:
        print("%-34s EXC %s" % (name, str(e)[:60]))
        return None

payloads = [
    ("empty CBOR after opcode",   bytes([0x01])),
    ("64-bit int head 0x1B",     bytes([0x01, 0x1B]) + b"\xff" * 8),
    ("deep nested arrays",        bytes([0x01, 0x81] * 32)),
    ("indefinite-length map",     bytes([0x01, 0xBF, 0xFF])),
    ("truncated map",             bytes([0x01, 0xA5, 0x01])),
    ("duplicate keys",            bytes([0x01]) + cbor2.dumps({1: b"a", 1: b"a", 1: b"a"})),
    ("huge string claim",         bytes([0x01, 0xA1, 0x01, 0x7B]) + b"\xff" * 16),
    ("opaque tag 6 (never used)", bytes([0x01, 0xC6, 0x81, 0x01])),
]
for name, p in payloads:
    cbor_raw(name, p)

# largeBlobs proper form: {1: get_len, 2: offset}
cbor_raw("largeBlobs get len=1024 off=0", bytes([0x0C]) + cbor2.dumps({1: 1024, 2: 0}), 5.0)
cbor_raw("largeBlobs set no auth", bytes([0x0C]) + cbor2.dumps({1: 1024, 2: 0, 4: b"\x00" * 64}))
cbor_raw("largeBlobs get len=huge", bytes([0x0C]) + cbor2.dumps({1: 2**31, 2: 0}), 5.0)

# --- 5. vendor channel 0x41 (frame-level, not CBOR) ---------------------
for sub in (0x0D, 0x20, 0x07):
    try:
        r = h._send_seq(cid, 0x41, bytes([sub, 0x01]) + b"\x00" * 16)
        r = h._recv(cid, 3.0)
        print("vendor 0x41 sub %02X -> %s" % (sub, r.hex()[:40]))
    except Exception as e:
        print("vendor 0x41 sub %02X EXC %s" % (sub, str(e)[:40]))

h.close()
print("alive at end:", alive())