# The 0x41 dialect probe: stock fapico2 board, on-board evidence — US-1751

Probe: `scripts/probe_picoforge_dialect.py` (the brief's deliverable name; the
first fix-round attempt had it under `probe_0x41_dialect.py` and renamed it).
Board: `/dev/hidraw1`, lsusb identity `fa20:0002 "The BLOCO Community fapico2"`
(stock AAGUID — no reflash, no override). Interpreter: the test venv
(`../pico-fido2/.test-venv/bin/python`, Python 3.12, fido2 2.2.1, pyscard 2.3.1);
the script byte-compiles under system python3 (fido2 1.2.0) too. Style model:
`2026-10-31-seed-restore-proof.md` raw-block discipline.

The probe imports `backup_fido.py`'s wire layer — `_vendor_mac`, `_build_request`,
`_vendor_call`, `_mse_handshake`, `_prose`, `_select_device`, `product_of` — in
the same sibling-script style `probe_seed_restore.py:50` uses. It sends only
getInfo, CONFIG_READ {1: PHY target}, STATE, the MSE handshake, EXPORT, and the
PC/SC rescue SELECT. LOAD / FINALIZE / CONFIG_WRITE are never sent; neither is
clientPIN/getPinRetries — PIN tokens are only ever accepted from outside via
`--pin-token`, so no PIN retry counter is charged either. Every vendor command
runs under an explicit 31 s SIGALRM budget (the brief's "each under 32 s", made
enforceable: a hung arm FAILs, it does not pass silently). STATE is fetched
exactly once — the raw map drives both the load-bearing no-key-5 assertion and
the flag summary.

## Fresh run 1 — EXPORT attempted (default), PC/SC observed

```console
$ ../pico-fido2/.test-venv/bin/python scripts/probe_picoforge_dialect.py --pcsc
using board at /dev/hidraw1 (product: The BLOCO Community fapico2)
board: /dev/hidraw1 (product: The BLOCO Community fapico2)
getInfo: version=['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3'] AAGUID=66617069636f32000000000000000002 versions=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 25, 29, 30, 31]
  (no stored PhyConfig overrides — stock board never CONFIG_WRITE'n)
STATE raw map: {1: False, 2: False, 3: False, 4: False}
STATE flags (same round-trip): seed=False sealed=False locked=False
MSE handshake (ungated ephemeral ECDH; no PIN token supplied)
EXPORT tokenless (touch-gated): touch the button on the fapico2 board at /dev/hidraw1 now… (if nobody can, it answers 0x3B/0x2D after the presence window)
EXPORT answered 0x2D (presence gate; nobody pressed on this host) — honest observation, not counted
PASS  AAGUID is the stock fa20:0002 identity: 66617069636f32000000000000000002
PASS  CONFIG_READ(0x0D) {1: 0x01 PHY-target} answers 0x00: status=0x00
PASS  CONFIG_READ returns a bytes blob under key 1: 0 TLV records, 0 bytes
PASS  STATE keys are a subset of {1,2,3,4}: keys=[1, 2, 3, 4]
PASS  NO key 5 in STATE (load-bearing)
PASS  MSE returns {1: COSE_Key} with a 65-byte uncompressed device point: len=65
PC/SC SELECT rescue AID: reader=fapico2 CCID (fapico2 firmware) (11778552) 00 00 SW=0x9000 len=12 body=010208007c36644dff8a74c7
PASS  PC/SC rescue SELECT data[2] (fw major) == 8: got 0x08
PC/SC header: MCU=0x01 product=0x02 fw=8.0 extra=7c36644dff8a74c7
DIALECT-OK
exit=0
```

## Fresh run 2 — the CI shape (`--no-touch` skip)

```console
$ ../pico-fido2/.test-venv/bin/python scripts/probe_picoforge_dialect.py --no-touch
using board at /dev/hidraw1 (product: The BLOCO Community fapico2)
board: /dev/hidraw1 (product: The BLOCO Community fapico2)
getInfo: version=['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3'] AAGUID=66617069636f32000000000000000002 versions=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 25, 29, 30, 31]
  (no stored PhyConfig overrides — stock board never CONFIG_WRITE'n)
STATE raw map: {1: False, 2: False, 3: False, 4: False}
STATE flags (same round-trip): seed=False sealed=False locked=False
MSE handshake (ungated ephemeral ECDH; no PIN token supplied)
EXPORT leg SKIPPED (--no-touch); the MSE channel times out by itself
PC/SC leg SKIPPED (--pcsc not requested)
PASS  AAGUID is the stock fa20:0002 identity: 66617069636f32000000000000000002
PASS  CONFIG_READ(0x0D) {1: 0x01 PHY-target} answers 0x00: status=0x00
PASS  CONFIG_READ returns a bytes blob under key 1: 0 TLV records, 0 bytes
PASS  STATE keys are a subset of {1,2,3,4}: keys=[1, 2, 3, 4]
PASS  NO key 5 in STATE (load-bearing)
PASS  MSE returns {1: COSE_Key} with a 65-byte uncompressed device point: len=65
DIALECT-OK
exit=0
```

## Reading it honestly

* **AAGUID stock**: `66617069636f3200…0002` — the board the probe ran against is
  the unmodified `fa20:0002`; nothing was reflashed for this transcript.
* **CONFIG_READ {1: PHY-target} answers 0x00 with `{1: b""}`** — an empty but
  present blob. A stock board that never ran CONFIG_WRITE has no PhyConfig
  records; the dialect shape is the status and key, not record count. `fix_usb_identity.py`'s
  reader accepts it; "no records" is not a failure and the probe says so.
* **STATE keys are exactly {1,2,3,4} — no key 5 ever appears.** This is US-1751's
  load-bearing line (and US-1755's input): the board's STATE map carries only
  sealed/has_seed/locked/unlocked. One round-trip feeds both this assertion and
  the `seed=False sealed=False locked=False` summary — no second STATE call.
* **MSE (ungated) returns a device COSE_Key whose point is 65 bytes** (`0x04‖x‖y`)
  — ephemeral ECDH opens on-board without any PIN token, so the RS-Key channel
  the EXPORT leg rides is real here, not just v0.
* **EXPORT attempted by default, answered 0x2D**: this board has no PIN set
  (confirmed by the presence gate opening at all — a PIN-set board would have
  answered 0x36 tokenless), so tokenless EXPORT is touch-gated; nobody was at
  the case for this scripted run, the window closed unpressed, and 0x2D is
  printed verbatim as an honest off-host observation — **not counted, never
  faked as 0x00**. The `--pin-token HEX` path (a PERM_ACFG pinUvAuthToken
  obtained elsewhere; `_build_request` + `_vendor_mac` put `{3: 1, 4: mac}` on
  the wire) is the BDD's "with a PIN set → EXPORT+MAC answers 0x00 {1: blob}"
  arm — documented in the script, not exercised here because this board has no
  PIN and minting one would need clientPIN, which the probe deliberately never
  sends.
* **PC/SC rescue SELECT reachable on this host**: AID `A0583FC19B7E4F21` (same
  APDU as `bootsel.py`), SW 0x9000, header `MCU=RP2350 product=0x02 fw-major
  8` — `data[2] = 0x08`. The PC/SC half of the dual-transport board is alive at
  fw 8.0, exactly what US-1754's reflash leg needs to see before flashing.

## What it does NOT claim

* EXPORT sealed-blob round-trip on-board: not claimed here (nobody pressed; the
  0x2D is honest and uncounted). The 2026-10-31 seed-restore audit covers a
  touched EXPORT restore path with a human present.
* The PIN-set EXPORT+MAC arm: this board has no PIN, so that arm is code-documented
  (and unit-testable against `vendor_backup.rs`'s status table), not on-board
  evidence here.
* CONFIG_WRITE/LOAD/FINALIZE behaviour: never sent, so nothing here speaks to them.

## Prior attempt (superseded — kept for the audit trail)

The fix round's first attempt ran under the old name `probe_0x41_dialect.py`
with an opt-in `--export`, a tokenless-only EXPORT arm (dead on a PIN-set board:
0x36, never MAC'd), STATE fetched twice, and no explicit per-command budget. Its
transcript — same board, same day — is reproduced below exactly as it printed
then (the only change is that the invocation line shows its pre-rename path):

```console
$ scripts/probe_0x41_dialect.py --export --pcsc
using board at /dev/hidraw1 (product: The BLOCO Community fapico2)
board: /dev/hidraw1 (product: The BLOCO Community fapico2)
getInfo: version=['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3'] AAGUID=66617069636f32000000000000000002 versions=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 25, 29, 30, 31]
  (no stored PhyConfig overrides — stock board never CONFIG_WRITE'n)
STATE raw map: {1: False, 2: False, 3: False, 4: False}
STATE flags: seed=False sealed=False locked=False
MSE handshake (ungated ephemeral ECDH; no PIN token offered)
Touch the button on the fapico2 board at /dev/hidraw1 now… (if nobody can, EXPORT will answer 0x3B after the presence window)
EXPORT answered 0x2D (presence gate; nobody pressed on this host) — honest observation, leg not counted
PASS  AAGUID is the stock fa20:0002 identity: 66617069636f32000000000000000002
PASS  CONFIG_READ(0x0D) {1: 0x01 PHY-target} answers 0x00: status=0x00
PASS  CONFIG_READ returns a bytes blob under key 1: 0 TLV records, 0 bytes
PASS  STATE keys are a subset of {1,2,3,4}: keys=[1, 2, 3, 4]
PASS  NO key 5 in STATE (load-bearing)
PASS  MSE returns {1: COSE_Key} with a 65-byte uncompressed device point: len=65
PC/SC SELECT rescue AID: reader=fapico2 CCID (fapico2 firmware) (11778552) 00 00 SW=0x9000 len=12 body=010208007c36644dff8a74c7
PASS  PC/SC rescue SELECT data[2] (fw major) == 8: got 0x08
PC/SC header: MCU=0x01 product=0x02 fw=8.0 extra=7c36644dff8a74c7
DIALECT-OK
exit=0
```


The on-board facts agree with the fresh runs; what died was the deliverable's
shape, not the evidence. The fix round renamed the script to the brief's name,
made EXPORT default-attempt with `--no-touch` skip and a real PERM_ACFG token
path, collapsed the double STATE fetch, and put every vendor call under the 31 s
budget.

## Reproduce

```console
scripts/probe_picoforge_dialect.py --pcsc            # fresh run 1 (EXPORT attempted)
scripts/probe_picoforge_dialect.py --no-touch        # fresh run 2 (CI shape)
scripts/probe_picoforge_dialect.py                   # EXPORT attempted, PC/SC skipped
```

`--device PATH` pins the board when more than one answers; `--pin-token HEX`
supplies an externally obtained PERM_ACFG pinUvAuthToken for the PIN-set arm.
The probe exits 0 printing `DIALECT-OK` iff every EXECUTED assertion passed;
skipped and device-refusal legs are reported and not counted.
