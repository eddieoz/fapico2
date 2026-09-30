# python-fido2 CTAP2 HID framing protocol

The exact wire format that `python-fido2` (the `fido2.hid.CtapHidDevice` / `CtapHidConnection`)
expects when talking to a CTAP2 authenticator over HID. Documented here because the
python-fido2 source is opaque and the error messages are cryptic (`struct.error:
unpack_from requires a buffer of at least 3 bytes`, `ConnectionFailure: Wrong channel`).

## Report format (what goes on the wire)

Every HID report is **64 bytes**, padded with `0x00`. The first 7 bytes are a header:

```
[channel_id: 4 bytes, big-endian uint32]
[cmd: 1 byte]       ; CTAPHID command OR (0x80 | cmd) for TYPE_INIT
[len: 2 bytes, big-endian uint16]  ; length of the remaining payload
```

The remaining bytes are the payload (up to 64 - 7 = 57 bytes per packet). Large
messages are fragmented across continuation packets:

```
Continuation packet header: [channel_id: 4 bytes] [seq: 1 byte, 0x00..0x7F]
Payload per packet: up to 57 bytes (first) / 59 bytes (continuation)
```

## python-fido2's `_do_call` expectations

```python
# fido2/hid/__init__.py
r_channel = struct.unpack_from(">I", recv)[0]
recv = recv[4:]                       # strip channel
if r_channel != self._channel_id:     # STRICT channel check
    raise ConnectionFailure("Wrong channel")
r_cmd = recv[0]
r_len = struct.unpack_from(">H", recv[1:3])[0]
payload = recv[3:3 + r_len]
```

**Critical detail:** the channel check happens BEFORE the command byte is parsed.
So the **response** must carry the SAME `channel_id` the request used.

## CTAPHID.INIT (0x06) — the special case

INIT is the only command that changes the channel. The protocol:

1. **Request:** host sends `channel_id = 0xFFFFFFFF`, cmd = 0x06, payload = 8-byte nonce.
2. **Response:** device MUST reply with `channel_id = 0xFFFFFFFF` (same as request!),
   then allocate a new channel and include it in the response payload.
3. **After:** host updates its `_channel_id` to the new channel from the payload.

**Response payload format:**
```
[nonce: 8 bytes]        ; echo the request nonce
[new_channel: 4 bytes]  ; big-endian uint32
[version: 1 byte]       ; 0x04 = CTAP2.1
[major: 1 byte]         ; protocol major
[minor: 1 byte]         ; protocol minor
[build: 1 byte]         ; build version
```

**Common mistake:** allocating a NEW channel in the response header. Don't —
the response header channel must be `0xFFFFFFFF` (the request's channel), not
the new channel. The new channel goes in the payload only.

## Wire format for our TCP shim

Since our `EmulationCtapHidConnection.write_packet` / `read_packet` already do
the `[u16 BE length]` framing, the emulator receives `report[7:]` (after `read_hid`
strips the outer length prefix) and must respond with a full HID report INCLUDING
the 7-byte header:

```
Response = [channel_id: 4] [cmd: 1] [len: 2] [status_byte: 1] [cbor_data...]
```

For INIT specifically:
```
Response = [0xFFFFFFFF: 4] [0x06: 1] [len=18: 2] [nonce: 8] [new_ch: 4] [0x04: 1] [0x01: 1] [0x00: 1] [0x00: 1]
```

For all other commands:
```
Response = [req_channel: 4] [req_cmd: 1] [len: 2] [0x00: 1] [cbor: ...]
```

## Debugging recipe

When the suite hangs or throws `struct.error`:

1. Add `print(f"DEBUG PY WRITE: {packet.hex()}")` to `write_packet`.
2. Add `print(f"DEBUG PY READ: {data.hex()}")` to `read_packet`.
3. In the emulator, `eprintln!("DEBUG IN: {} bytes: {:02x?}", frame.len(), &frame)`.
4. Compare: the READ output should start with the same 4 bytes as the request
   channel, then the command byte, then the length, then at least 1 byte of payload.
5. If READ returns only 2 bytes, `read_packet`'s `size` was 2 → the emulator wrote
   a 2-byte response → check the response construction in `emul_main.rs`.

## Non-blocking I/O pitfall

The emulator's main loop does non-blocking `accept()` + `read_ccid()` + `read_hid()`.
If `read_hid()` returns `None` (no data yet), the loop sleeps 10ms and retries.
This is correct for a test transport but means there's a brief window after
`write_packet` where the emulator hasn't processed the request yet. The harness
has a 1s sleep after starting the emulator for this reason — do NOT reduce it.

## Channel lifecycle

1. `list_descriptors()` → returns `HidDescriptor` with metadata
2. `open_connection()` → opens TCP socket
3. `CtapHidDevice.__init__` → calls `self.call(CTAPHID.INIT, nonce)`
   - Allocates `_channel_id` from INIT response payload
4. All subsequent calls use `_channel_id` from step 3.

If the INIT response has the wrong channel in the header (not `0xFFFFFFFF`),
python-fido2 raises `ConnectionFailure: Wrong channel` immediately.
