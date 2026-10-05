"""CTAPHID framing abuse on a single persistent fd, plus the INIT-preemption
race the firmware documents as an exemption (US-705.1).
"""
import os, struct, time, select, sys
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")

DEV = "/dev/hidraw8"
fd = os.open(DEV, os.O_RDWR | os.O_NONBLOCK)

def drain(t=0.3):
    out = []
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                d = os.read(fd, 65)
                if len(d) == 65: d = d[1:]
                out.append(d)
            except (BlockingIOError, OSError):
                break
    return out

def w(f):
    os.write(fd, b"\x00" + f.ljust(64, b"\x00")[:64])

def frame(cid, cmd, data=b""):
    return struct.pack(">IBH", cid, cmd, len(data)) + data

def fresh_cid():
    w(frame(0xFFFFFFFF, 0x86, b"\x00" * 8))
    r = drain(0.5)
    return struct.unpack(">I", r[0][8:12])[0] if r else None

drain(0.3)
print("=== PING payload-size abuse (single fd) ===")
for n in (0, 1, 57, 7608, 7609, 7610):
    cid = fresh_cid()
    if cid is None:
        print("  n=%-6d no cid" % n); continue
    w(frame(cid, 0x81, b"A" * n))
    print("  PING len %-6d -> %s" % (n, [x.hex()[:20] for x in drain(0.5)] or "no reply"))

print("\n=== Framing abuse ===")
cid = fresh_cid() or 0x1234
abuse = [
    ("BCNT huge (0xFFFF)",   struct.pack(">IBH", cid, 0x81, 0xFFFF) + b"X" * 10),
    ("seq starts at 1",      struct.pack(">IBH", cid, 0x81, 200) + b"X" * 57 +
                            struct.pack(">IB", cid, 0x81) + b"Y" * 59),
    ("reserved CID 0",       frame(0x00000000, 0x86, b"\x00" * 8)),
    ("bridge CID [0,0,0,1]", frame(0x00000001, 0x81, b"X" * 8)),
    ("broadcast non-INIT",   frame(0xFFFFFFFF, 0x81, b"X" * 8)),
    ("type bit clear",       struct.pack(">IBH", cid, 0x01, 8) + b"X" * 8),
]
for name, f in abuse:
    w(f)
    r = drain(0.5)
    print("  %-22s -> %s" % (name, [x.hex()[:24] for x in r] or "no reply"))

print("\n=== INIT preemption race (US-705.1 exemption) ===")
# start a multi-frame PING, then blast INIT mid-transaction, then finish.
# If the firmware honours the exemption, the INIT reply preempts; if the
# busy guard is wrong, we either deadlock or corrupt the reassembly state.
for trial in range(5):
    cid = fresh_cid()
    big = b"Z" * 300
    w(struct.pack(">IBH", cid, 0x81, len(big)) + big[:57])
    w(frame(0xFFFFFFFF, 0x86, b"\x00" * 8))            # INIT mid-transaction
    w(struct.pack(">IB", cid, 0x80) + big[57:116])    # continue the PING
    w(struct.pack(">IB", cid, 0x81) + big[116:175])
    w(struct.pack(">IB", cid, 0x82) + big[175:234])
    w(struct.pack(">IB", cid, 0x83) + big[234:293])
    r = drain(0.6)
    kinds = []
    for x in r:
        kinds.append(("INIT" if x[4] == 0x86 else "PING" if x[4] == 0x81 else "ERR" if x[4] == 0xBF else hex(x[4])))
    print("  trial %d replies: %s" % (trial, kinds))

# after all that abuse the channel must still work
cid = fresh_cid()
w(frame(cid, 0x81, b"FINAL"))
r = drain(0.5)
print("\npost-race PING on fresh cid ->", [x[:12].hex() for x in r] or "no reply")
os.close(fd)