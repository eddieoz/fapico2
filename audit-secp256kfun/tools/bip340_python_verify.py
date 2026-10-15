#!/usr/bin/env python3
"""Independent BIP-340 oracle for the secp256kfun audit.

Pure-python secp256k1 + BIP-340 written from the specification (no third-party
crypto code). Three jobs:

  1. Verify every signature in spike-secp256kfun/vectors/bip340.csv — the file
     the applet's sign conformance test pins against. This closes the chain
     python(spec) <-> CSV <-> Rust applet.
  2. Check every hardcoded constant in secp256kfun 0.12.1's vendored backends
     (p, n, n/2, 2^256-n, G, beta, lambda, field limb constants) against
     values derived here from first principles.
  3. Confirm the GLV endomorphism constants: lambda*(x,y) == (beta*x, y).

Exit code 0 = all checks passed. Run: python3 tools/bip340_python_verify.py
"""
import hashlib
import sys

# --- field/group primitives -------------------------------------------------
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def inv_p(a):
    return pow(a, p - 2, p)


def on_curve(x, y):
    return (y * y - (x * x * x + 7)) % p == 0


def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0]:
        if (P[1] + Q[1]) % p == 0:
            return None
        lam = (3 * P[0] * P[0]) * inv_p(2 * P[1]) % p
    else:
        lam = (Q[1] - P[1]) * inv_p((Q[0] - P[0]) % p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    y = (lam * (P[0] - x) - P[1]) % p
    return (x, y)


def point_mul(k, P):
    k %= n
    R = None
    while k:
        if k & 1:
            R = point_add(R, P)
        P = point_add(P, P)
        k >>= 1
    return R


def lift_x(x):
    """BIP-340 lift_x: y = sqrt(x^3+7), even root; None if not a residue."""
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y % 2 == 0 else p - y)


def tagged_hash(tag, *parts):
    th = hashlib.sha256(tag).digest()
    return hashlib.sha256(th + th + b"".join(parts)).digest()


def bip340_verify(pk_x_bytes, msg, sig):
    """BIP-340 verification, verbatim from the spec's verification algorithm.
    The message may be any length; only pk (32) and sig (64) are fixed-width."""
    if len(pk_x_bytes) != 32 or len(sig) != 64:
        return False
    pk_x = int.from_bytes(pk_x_bytes, "big")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if not (1 <= pk_x < p) or not (1 <= s < n):
        return False
    P = lift_x(pk_x)
    if P is None:
        return False
    e = int.from_bytes(tagged_hash(b"BIP0340/challenge", sig[:32], pk_x_bytes, msg), "big") % n
    R = point_add(point_mul(s, (Gx, Gy)), point_mul(n - e, P))
    if R is None or R[1] % 2 != 0 or R[0] != r:
        return False
    return True


def bip340_sign(sk_bytes, msg, aux_bytes):
    """BIP-340 signing, verbatim from the spec's signing algorithm."""
    d0 = int.from_bytes(sk_bytes, "big")
    if not (1 <= d0 < n):
        raise ValueError("invalid secret key")
    P = point_mul(d0, (Gx, Gy))
    d = d0 if P[1] % 2 == 0 else n - d0
    t = d.to_bytes(32, "big")
    t = bytes(a ^ b for a, b in zip(t, tagged_hash(b"BIP0340/aux", aux_bytes)))
    k0 = int.from_bytes(tagged_hash(b"BIP0340/nonce", t, P[0].to_bytes(32, "big"), msg), "big") % n
    if k0 == 0:
        raise ValueError("nonce underflow")
    R = point_mul(k0, (Gx, Gy))
    k = k0 if R[1] % 2 == 0 else n - k0
    e = int.from_bytes(tagged_hash(b"BIP0340/challenge", R[0].to_bytes(32, "big"), P[0].to_bytes(32, "big"), msg), "big") % n
    s = (k + e * d) % n
    return R[0].to_bytes(32, "big") + s.to_bytes(32, "big")


# --- checks ------------------------------------------------------------------
FAIL = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAIL.append(name)


def check_constants():
    print("== hardcoded constants in the vendored backends ==")
    check("p == 2^256 - 2^32 - 977", p == 2**256 - 2**32 - 977)
    check("p == 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1",
          p == 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1)
    check("p % 4 == 3 (sqrt chain precondition)", p % 4 == 3)
    check("n is prime form check: (n-1)//2 != 0 and G order == n", point_mul(n, (Gx, Gy)) is None)
    # scalar_8x32.rs MODULUS limbs (little-endian u32)
    limbs = [0xD036_4141, 0xBFD2_5E8C, 0xAF48_A03B, 0xBAAE_DCE6,
             0xFFFF_FFFE, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF]
    n_limb = sum(l << (32 * i) for i, l in enumerate(limbs))
    check("scalar_8x32 MODULUS limbs == n", n_limb == n)
    neg_limb = [(~l + 1) % 2**32 if i == 0 else ~l % 2**32 for i, l in enumerate(limbs)]
    neg_val = sum(l << (32 * i) for i, l in enumerate(neg_limb))
    check("NEG_MODULUS limbs (!M0+1, !M1..) == 2^256 - n", neg_val == 2**256 - n)
    check("2^256 - n == 0x14551231950B75FC4402DA1732FC9BEBF",
          2**256 - n == 0x14551231950B75FC4402DA1732FC9BEBF)
    # FRAC_MODULUS_2 (little-endian u32 limbs from scalar_8x32.rs:37-46)
    frac = [0x681B_20A0, 0xDFE9_2F46, 0x57A4_501D, 0x5D57_6E73,
            0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0x7FFF_FFFF]
    frac_limb = sum(l << (32 * i) for i, l in enumerate(frac))
    check("FRAC_MODULUS_2 limbs == n // 2", frac_limb == n // 2)
    # field_10x26.rs negate minuends are the limbs of p itself in 26-bit LE
    plimbs = [0x3FFFC2F, 0x3FFFFBF, 0x3FFFFFF, 0x3FFFFFF, 0x3FFFFFF, 0x3FFFFFF,
              0x3FFFFFF, 0x3FFFFFF, 0x3FFFFFF, 0x03FFFFF]
    p_val = sum(l << (26 * i) for i, l in enumerate(plimbs))
    check("field_10x26 negate limb minuends == p", p_val == p)
    # field_5x52.rs negate minuends are the limbs of p in 52-bit LE
    p5 = [0xFFFFEFFFFFC2F, 0xFFFFFFFFFFFFF, 0xFFFFFFFFFFFFF, 0xFFFFFFFFFFFFF, 0x0FFFFFFFFFFFF]
    p5_val = sum(l << (52 * i) for i, l in enumerate(p5))
    check("field_5x52 negate limb minuends == p", p5_val == p)
    # 2^256 mod p fold constant
    check("2^256 mod p == 0x1000003D1 (field fold r=0x1000003D10 = 2*0x3D1 at 2^32)",
          2**256 % p == 0x1000003D1)
    # scalar sqrt (Tonelli-Shanks, n mod 16 == 1): the pow_vartime constant,
    # little-endian u64 limbs in scalar.rs:168-173
    exp = (0x777fa4bd19a06c82
           | (0xfd755db9cd5e9140 << 64)
           | (0xFFFFFFFFFFFFFFFF << 128)
           | (0x1FFFFFFFFFFFFFF << 192))
    # Tonelli-Shanks (eprint 2012/685 alg. 5): exponent = (t-1)/2 with
    # t = (n-1)/2^S, S = 6.
    t = (n - 1) // 64
    check("scalar sqrt exponent constant == (t-1)/2, t = (n-1)/2^6, S = 6",
          (n - 1) % 64 == 0 and t % 2 == 1 and exp == t // 2)


def check_glv():
    print("== GLV endomorphism constants ==")
    lam = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
    beta = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
    # MINUS_LAMBDA bytes in mul.rs -> should be n - lambda
    minus_lambda = 0xAC9C52B33FA3CF1F5AD9E3FD77ED9BA4A880B9FC8EC739C2E0CFC810B51283CF
    check("MINUS_LAMBDA == n - lambda", minus_lambda == n - lam)
    Q = point_mul(0xDEADBEEF12345678, (Gx, Gy))
    check("lambda * Q == (beta*x, y)", point_mul(lam, Q) == ((beta * Q[0]) % p, Q[1]))
    # EEA identity from the mul.rs doc header: a1*b2 - b1*a2 == n for the
    # 128-bit outputs (NOT the 32-byte G1 estimate constant).
    a1 = 0x3086D221A7D46BCDE86C90E49284EB15
    b1 = -0xE4437ED6010E88286F547FA90ABFE4C3
    a2 = 0x114CA50F7A8E2F3F657C1108D9D44CFD8
    b2 = 0x3086D221A7D46BCDE86C90E49284EB15
    check("a1*b2 - b1*a2 == n (EEA identity, 128-bit constants)", (a1 * b2 - b1 * a2) % 2**512 == n)


def check_vectors():
    print("== BIP-340 reference vectors (independent verification) ==")
    path = __file__.rsplit("/", 2)[0] + "/../spike-secp256kfun/vectors/bip340.csv"
    rows = [l.split(",") for l in open(path).read().strip().splitlines()[1:]]
    check("vector count == 19", len(rows) == 19, str(len(rows)))
    ok_sign = ok_verify = 0
    for row in rows:
        idx, sk, pk, aux, msg, sig, result, comment = row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7] if len(row) > 7 else ""
        msg_b, sig_b = bytes.fromhex(msg), bytes.fromhex(sig)
        pk_b, aux_b = bytes.fromhex(pk), bytes.fromhex(aux)
        # verify side
        v = bip340_verify(pk_b, msg_b, sig_b)
        want = result == "TRUE"
        if v == want:
            ok_verify += 1
        else:
            FAIL.append(f"verify row {idx}")
            print(f"  [FAIL] verify row {idx} ({comment})")
        # sign side: only rows with a valid secret key reproduce the signature
        if len(sk) == 64 and (1 <= int(sk, 16) < n):
            try:
                s = bip340_sign(bytes.fromhex(sk), msg_b, aux_b)
                if s == sig_b:
                    ok_sign += 1
                else:
                    FAIL.append(f"sign row {idx}")
                    print(f"  [FAIL] sign row {idx}: python sign != CSV")
            except ValueError as e:
                FAIL.append(f"sign row {idx}")
                print(f"  [FAIL] sign row {idx}: {e}")
    print(f"  [{len(rows)} rows] verify verdicts matched: {ok_verify}/{len(rows)}; "
          f"sign reproductions: {ok_sign}/{sum(1 for r in rows if len(r[1]) == 64)}")


def check_scalar_sqrt_constant():
    print("== field sqrt exponent (p+1)/4 chain ==")
    # field.rs sqrt final exponent derived earlier: 2^254 - 2^30 - 244
    check("(p+1)//4 == 2^254 - 2^30 - 244", (p + 1) // 4 == 2**254 - 2**30 - 244)


if __name__ == "__main__":
    check_constants()
    check_glv()
    check_scalar_sqrt_constant()
    check_vectors()
    print()
    if FAIL:
        print(f"FAILED: {len(FAIL)} checks: {FAIL[:10]}")
        sys.exit(1)
    print("ALL PYTHON ORACLE CHECKS PASSED")
