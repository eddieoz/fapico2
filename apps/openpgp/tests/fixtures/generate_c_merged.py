#!/usr/bin/env python3
"""Independent KAT encoder of the local merged C producer (not Rust roundtrip).

Sources: pico-fido2/src/openpgp/{key_container.c,openpgp.c,object_provider.c},
pico-keys-sdk/src/fs/{object_container.c,object_container_store.c,object_policy.c}.
Note producer record_fid uses private_prefix + 1 for public, NOT the unused
PUBLIC_SLOT constants. Container id passed to update is the FULL logical FID.
"""
from pathlib import Path
import hashlib, hmac, struct
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hk(key,info,salt=None):
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=info).derive(key)
def mac(key,data): return hmac.new(key,data,hashlib.sha256).digest()
def be(n,size): return n.to_bytes(size,'big')
uid=bytes(range(1,9)); sh=hashlib.sha256(uid).digest()
otp=bytes(range(0xa0,0xc0)); root=hk(otp,b'DEVICE/ROOT',sh)
dek=bytes(range(0x60,0x90))
def verifier(pin): return bytes([len(pin),1])+hk(mac(root,pin),b'PIN/VERIFY',sh)
def wrapper(pin):
    session=hk(mac(root,pin),b'PIN/TOKEN',sh)
    key=hk(root+session,b'PIN/ENC2',sh); nonce=bytes(range(0x70,0x7c))
    return b'\x03'+nonce+AESGCM(key).encrypt(nonce,dek,sh)
secret=bytes.fromhex('519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464')
public=b'\x7f\x49\x43\x86\x41'+ec.derive_private_key(int.from_bytes(secret,'big'),ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
policy=bytes.fromhex('01011fff000004600000000000010000')
ph=hashlib.sha256(policy).digest()[:16]
def key_records(fid, private, public):
    ns=5; kind=1; generation=1
    records=[]; descriptors=[]
    slot=fid & 255
    for typ,rid,protection,flags,plain,r in [(1,0xea00|slot,2,6,private,dek[16:]),(2,0xeb00|slot,1,10,public,root)]:
        n=len(plain)
        desc=struct.pack('>HHIIQI HBBHHHH',typ,0,generation,n,rid,n,0x500,0,protection,flags,0,0,0)
        descriptors.append(desc)
        nonce=be(rid,8)+be(generation,4)
        aad=b'PKOR'+b'\x01'+be(ns,2)+be(kind,2)+be(fid,4)+be(typ,2)+be(0,2)+be(generation,4)+be(n,4)+be(0x500,2)+ph+bytes([0,protection])+be(flags,2)+be(rid,8)
        domain=hk(r,be(ns,2)+b'\0PKOC/domain/v1')
        key=hk(domain,b'PKOC/object/v1'+aad)
        sealed=AESGCM(key).encrypt(nonce,plain,aad) if protection==2 else plain+mac(key,aad+nonce+plain)[:16]
        header=b'PKOR'+bytes([1,protection])+be(40,2)+be(rid,8)+be(n,4)+be(n,4)+be(generation,4)+nonce
        records.append((rid,header+sealed))
    manifest=b'PKOC'+bytes([1,32])+be(0,2)+be(ns,2)+be(kind,2)+be(fid,4)+be(1,4)+be(0,4)+be(2,2)+bytes([36,0])+be(0,2)+be(120,2)+b''.join(descriptors)
    manifest+=mac(hk(root,be(ns,2)+b'PKOC/manifest/v1'),manifest)[:16]
    return records+[(0xe800|slot,manifest),(fid,b'PKG1\x01'+be(fid,2)+bytes(3)),(fid+3,public)]

records = key_records(0x10d1, b'\x03'+secret, public)
records += [
            (0x1081,verifier(b'654321')),(0x1083,verifier(b'87654321')),
            (0x109a,wrapper(b'654321')),(0x109c,wrapper(b'87654321')),
            (0x10c4,bytes([1,127,127,127,3,0,3])),(0x10c5,bytes([1,3,3,3,3,3,0])),
            (0x10c1,bytes.fromhex('132a8648ce3d030107')),(0x005b,b'Migrated User'),
            (0x00c7,bytes(range(20))),(0x00ce,bytes.fromhex('65010203')),(0x0093,bytes([0,0,7]))]
out=Path(__file__).parent
(out/'c-merged-p256.bin').write_bytes(b''.join(struct.pack('<HI',f,len(v))+v for f,v in records))
(out/'c-merged-p256-public.bin').write_bytes(public)
print(f'{len(records)} producer-format records, {sum(6+len(v) for _,v in records)} bytes')

# mbedtls_ecp_write_key_ext serializes Montgomery scalars little-endian.
xsecret=bytearray(range(32)); xsecret[0]&=248; xsecret[31]=(xsecret[31]&127)|64
xkey=x25519.X25519PrivateKey.from_private_bytes(bytes(xsecret))
xpublic=b'\x7f\x49\x22\x86\x20'+xkey.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
peer=x25519.X25519PrivateKey.from_private_bytes(bytes(range(32,64)))
peer_public=peer.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
xrecords=records+key_records(0x10d2,b'\x09'+bytes(xsecret),xpublic)+[
    (0x10c2,bytes.fromhex('122b060104019755010501')),
    (0x00c8,bytes(range(20,40))),(0x00cf,bytes.fromhex('65010204'))]
(out/'c-merged-x25519.bin').write_bytes(b''.join(struct.pack('<HI',f,len(v))+v for f,v in xrecords))
(out/'c-merged-x25519-public.bin').write_bytes(xpublic)
(out/'c-merged-x25519-peer.bin').write_bytes(peer_public)
(out/'c-merged-x25519-shared.bin').write_bytes(xkey.exchange(peer.public_key()))

authsecret=bytes(range(1,33))
authpublic=b'\x7f\x49\x43\x86\x41'+ec.derive_private_key(int.from_bytes(authsecret,'big'),ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
auth=key_records(0x10d3,b'\x03'+authsecret,authpublic)+[
    (0x10c3,bytes.fromhex('132a8648ce3d030107')),
    (0x00c9,bytes(range(40,60))),(0x00d0,bytes.fromhex('65010205'))]
authrecords=records+auth
(out/'c-merged-three-key.bin').write_bytes(b''.join(struct.pack('<HI',f,len(v))+v for f,v in xrecords+auth))
(out/'c-merged-auth-p256.bin').write_bytes(b''.join(struct.pack('<HI',f,len(v))+v for f,v in authrecords))
(out/'c-merged-auth-p256-public.bin').write_bytes(authpublic)

# Authenticated negative private objects: valid earlier signing identity, not
# ciphertext tampering. Rebuild manifests/descriptors/tags for each plaintext.
for name, fid, private, captured_public in [
    ('later-tag', 0x10d3, b'\x09'+authsecret, authpublic),
    ('later-length', 0x10d2, b'\x09'+bytes(xsecret[:-1]), xpublic),
    ('later-auth-mismatch', 0x10d3, b'\x03'+secret, authpublic),
    ('later-dec-mismatch', 0x10d2, b'\x09'+bytes(range(32,64)), xpublic),
]:
    replacement = key_records(fid, private, captured_public)
    replaced = {f for f, _ in replacement}
    negative = [(f, v) for f, v in xrecords+auth if f not in replaced]+replacement
    (out/f'c-merged-{name}.bin').write_bytes(
        b''.join(struct.pack('<HI', f, len(v))+v for f,v in negative))

# Profile coverage: deliberately unsupported keyless RSA attribute and native DOs.
for filename, extra in [
    ('c-merged-unsupported-algorithm.bin', [(0x10c2, bytes.fromhex('010800002000'))]),
    ('c-merged-profile.bin', [(0x5f2d, b'enpt'), (0x5f35, b'2'),
                              (0x0101, b'public private DO one'),
                              (0x0102, b'public private DO two')]),
]:
    (out/filename).write_bytes(b''.join(struct.pack('<HI', f, len(v))+v for f,v in records+extra))
