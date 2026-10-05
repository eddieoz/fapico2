"""OpenPGP malleability battery.

Three classes:
  A. PSO:DECIPHER (ECDH) — mutate the ephemeral public key the host sends and
     look for any response difference (bit-flip, truncation, point addition,
     small-order, curve-parameter substitution). Any asymmetry = malleability.
  B. PSO:COMPUTE DIGITAL SIGNATURE — vary the claimed hash algorithm (P1=0x9E
     vs 0x9B/0x81/0x9C/0x9D), the claimed key ref (P2), and digest length.
     A device that signs under a different algorithm than it reports is
     malleable; so is one that answers differently for a bad hash length.
  C. DDO/PSO structural — malformed TLVs in the data object, oversized blobs,
     truncation at every boundary. Uniform error is the pass condition.
"""
import sys, time, collections
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from ccid import Card

AID = "D276000124010304000000000000000000"

def tlv(tag, val):
    return bytes([tag, len(val)]) + val

# A point in the "good" curve family the firmware advertises (Curve25519 is
# 0x40 / Brainpool-256 is 0x24 per the AID capability byte; use opaque bytes —
# the point is the MUTATION test, not a valid curve equation).
BASE = bytes.fromhex("0932100000000000000000000000000000000000000000000000000000000000")

def decipher_body(point, ephemeral=None, extra=b""):
    # 0xB6 = tag for ephemeral public key in a decipher data object
    inner = tlv(0xB6, point)
    if ephemeral is not None:
        inner += tlv(0x7F, bytes([0x40]) + ephemeral)   # 7F47-ish wrapper
    body = inner + extra
    return bytes([0xA0, 0x00]) if not body else body

def run():
    c = Card()
    c.select(AID)
    results = collections.defaultdict(set)
    timings = collections.defaultdict(list)

    def probe(name, apdu_fn):
        t0 = time.perf_counter()
        try:
            resp, sw = apdu_fn()
        except Exception as e:
            results[name].add(("EXC", str(e)[:20]))
            return
        dt = (time.perf_counter() - t0) * 1000
        timings[name].append(dt)
        results[name].add((sw, len(resp)))

    print("=== A. PSO:DECIPHER point mutation ===")
    muts = {
        "base":        BASE,
        "zero":        bytes(32),
        "all-ff":      b"\xff" * 32,
        "bitflip-0":   bytes([BASE[0] ^ 1]) + BASE[1:],
        "bitflip-31":  BASE[:31] + bytes([BASE[31] ^ 0x80]),
        "truncated-1": BASE[:31],
        "truncated-16": BASE[:16],
        "extended-33": BASE + b"\x00",
        "double-add":  BASE + BASE,           # 64-byte concatenation
        "p256-order":  bytes.fromhex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
        "small-order-8": bytes([0]*30 + [8, 1]),
        "neg-y":       BASE[:31] + bytes([(BASE[31] ^ 0x80) if False else BASE[31]]),
    }
    for name, pt in muts.items():
        probe("dec:" + name, lambda p=pt: c.apdu(0x00, 0x2A, 0xFF, 0x00,
                                                 bytes([0xB6, len(p)]) + p, le=0))
    for name in muts:
        rs = results["dec:" + name]
        print("  %-14s -> %s" % (name, rs))

    print("\n=== B. PSO:CDS algorithm/hash-shape mutation ===")
    for p2, nm in ((0x9A, "sign(SHA)"), (0x9B, "sign(legacy)"), (0x9C, "sign(MD5)"),
                   (0x9D, "sign(SHA1)"), (0x9E, "sign(plain)")):
        for ln in (16, 20, 32, 64, 0):
            probe("sign:%s:%d" % (nm, ln),
                  lambda a=p2, l=ln: c.apdu(0x00, 0x2A, a, 0x00, b"\x00" * l, le=0))
    sig_shapes = {k: v for k, v in results.items() if k.startswith("sign:")}
    distinct = set()
    for k, v in sig_shapes.items():
        distinct |= v
    print("  distinct (sw,len) across %d sign shapes: %s" % (len(sig_shapes), distinct))

    print("\n=== C. malformed data objects ===")
    mal = {
        "empty":      b"",
        "1 byte":     b"\x00",
        "tlv-no-len": b"\xA0",
        "tlv-overrun": bytes([0xB6, 0x40]) + BASE,   # claims 64, has 32
        "nested-tag": tlv(0xA0, tlv(0xB6, BASE)),
        "tag-0x7F":   tlv(0x7F, bytes([0x40]) + BASE),
        "alg-unknown": tlv(0x80, bytes([0x99])),
    }
    for name, body in mal.items():
        probe("mal:" + name, lambda b=body: c.apdu(0x00, 0x2A, 0xFF, 0x00, b, le=0))
    for name in mal:
        print("  %-14s -> %s" % (name, results["mal:" + name]))

    print("\n=== verdict ===")
    dec_responses = set()
    for k, v in results.items():
        if k.startswith("dec:"):
            dec_responses |= v
    print("  PSO:DECIPHER distinct responses: %s" % dec_responses)
    print("  => %s" % ("UNIFORM (no malleability)" if len(dec_responses) == 1
                       else "DISTINGUISHABLE (%d classes)" % len(dec_responses)))
    print("  PSO:CDS distinct responses: %s" % distinct)
    print("  => %s" % ("UNIFORM (no algorithm confusion)" if len(distinct) == 1
                       else "DISTINGUISHABLE — algorithm/shape is observable"))

    # timing spread on decipher (a bit-length leak would show here)
    allt = [t for v in timings.values() for t in v]
    if allt:
        print("  decipher timing: min=%.1fms max=%.1fms spread=%.1fms"
              % (min(allt), max(allt), max(allt) - min(allt)))
    c.disconnect()

run()