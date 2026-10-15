# US-1704 — the PIN custody legs on the flashed board (CCID)

Firmware: the custody build (`firmware/fapico2.uf2`, sha256
`f7583afda00ed79fe997fa2b4c8c7cb6db9fdc3236c139c9dd1adce21d38bcd0`),
flashed over BOOTSEL 2026-10-15; the board re-enumerated as
`fa20:0002 The BLOCO Community fapico2`. Driver: `scripts/nostr_probe.py
--pin` over CCID; the PIN was fed through a pty (getpass needs a tty).

```
Nostr applet selected via fapico2 CCID (fapico2 firmware) (11778552) 00 00

[P1] SET_PIN
  -> SW=0x9000 (expect 9000; 6A82 = already set)

[P2] SIGN while locked — the gate word
  -> SW=0x6982 (expect 0x6982 before any touch prompt)

[P3] VERIFY_PIN
  -> SW=0x9000 (expect 9000)

[P4] two wrong VERIFYs then the right one — the 63CX rows
  -> SW=0x63c2 (expect 63C2, then 63C1)
  -> SW=0x63c1 (expect 63C2, then 63C1)
  -> SW=0x9000 (expect 9000; the success resets the counter)

[P5] LOCK
  -> SW=0x9000 (expect 9000)

[P6] verify survives deselect: re-select the applet, then VERIFY
  -> SW=0x9000 (expect 9000 — the session is applet-global, not per-connection)

--pin legs done; the full gated-command matrix is the emulator suite's
```

Every leg matched its expectation:

- **P1** the fresh board accepted SET_PIN (`9000`) — the PinRecord took.
- **P2** the gated command refused `6982` **before any touch prompt** — the
  gate sits in front of the touch, the ordering US-1698's tests pin.
- **P3** the correct PIN opened the session.
- **P4** the attempt counter counts down `63C2` → `63C1` and the successful
  verify resets it — the durable 63CX rows, measured on silicon.
- **P5** LOCK answered `9000`.
- **P6** after a full deselect/re-select of the AID, the PIN was still
  accepted without re-entry beyond the verify — the session is
  applet-global, not per-connection.

**The PIN on this board is `165042`** — a probe PIN established by the
transcript above. Change it with the CHANGE form (`0x4C`, P1=1) or clear it
with management RESET; it is not a production secret.

The HID arm of this dialect is exercised by the extension (US-1705..1707)
and the firmware host tests driving `process_vendor_through`; the emulator
never exposes the Nostr HID interface (AGENTS.md §8).
