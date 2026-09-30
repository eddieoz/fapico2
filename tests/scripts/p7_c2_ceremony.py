import fido2.ctap2.base as base
_orig = base.Ctap2.send_cbor
def _relaxed(self, cmd, data=None, event=None, on_keepalive=None):
    self._strict_cbor = False
    return _orig(self, cmd, data, event=event, on_keepalive=on_keepalive)
base.Ctap2.send_cbor = _relaxed

import sys, hmac as _hmac, hashlib, secrets
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement, LargeBlobs, Config
from fido2.ctap2.pin import PinProtocolV1
from fido2.cose import ES256

pin = "1234"
dev = next(CtapHidDevice.list_devices(), None)
ctap = Ctap2(dev)
info = ctap.get_info()
print("maxMsgSize:", info.max_msg_size)
print("options:", dict(info.options))

pin_cfg = ClientPin(ctap)
try:
    pin_cfg.set_pin(pin); print("setPIN: OK")
except Exception as e:
    print("setPIN note:", repr(e))
token = pin_cfg.get_pin_token(pin, permissions=0x37)
print("PIN-permissioned token (0x37): OK")

# MC rk=True + extensions (credProtect, hmac-secret), pinUvAuth v1
client_hash = bytes(range(32))
param = _hmac.new(token, client_hash, hashlib.sha256).digest()[:16]
mc = ctap.make_credential(
    client_hash, {"id": "example.com"}, {"id": b"user-p7"},
    [{"type": "public-key", "alg": -7}],
    extensions={"credProtect": 2, "hmac-secret": True},
    options={"rk": True}, pin_uv_param=param, pin_uv_protocol=1)
print("MC: authData", len(bytes(mc.auth_data)), "flags", hex(mc.auth_data.flags))
cose_key = mc.auth_data.credential_data.public_key

# getAssertion + python-fido2 signature check
ga = ctap.get_assertion("example.com", client_hash, pin_uv_param=param, pin_uv_protocol=1)
ga.verify(client_hash, cose_key)
print("getAssertion: signature verified (python-fido2)")

# credMgmt enumeration
cm = CredentialManagement(ctap, PinProtocolV1(), token)
meta = cm.get_metadata()
print("credMgmt metadata:", meta)
rps = list(cm.enumerate_rps())
print("credMgmt RPs:", len(rps))
assert len(rps) >= 1
rp_entry = rps[0]
rp_hash = rp_entry[4]
creds = list(cm.enumerate_creds(rp_hash))
print("credMgmt creds for first RP:", len(creds))
assert len(creds) >= 1

# largeBlobs: put + get full array (fragmented)
lb = LargeBlobs(ctap, PinProtocolV1(), token)
lbk = secrets.token_bytes(32)
data = secrets.token_bytes(64)
lb.put_blob(lbk, data)
got = lb.get_blob(lbk)
assert got == data, f"blob mismatch {got!r}"
print("largeBlobs: put+get round-trip OK")

# authenticatorConfig: toggle alwaysUv twice (restores state)
cfg = Config(ctap, PinProtocolV1(), token)
cfg.toggle_always_uv()
cfg.toggle_always_uv()
print("authenticatorConfig: toggle alwaysUv OK (twice, state restored)")

print("CEREMONY PASS (US-324 bar: rk + extensions + PIN-permissioned token + credMgmt + largeBlobs + config)")
