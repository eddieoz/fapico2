# Hardware acceptance matrix — US-391 (Phase 6)

Board: Raspberry Pi Pico 2 (RP2350), single USB composite device
(CCID + CTAP-HID). Firmware: `fapico2` Rust release build, flashed as
`firmware/fapico2.uf2`.

**USB identity used in this evidence:** `FA20:0002`, product "fapico2", no
serial. The **manufacturer** was "EddieOz" for every run recorded below; it was
renamed to "The BLOCO Community" on 2026-09-28 and the rename takes effect with
the first build that carries it. Only the `iManufacturer` string changes —
`FA20:0002` is untouched, so the CCID/pcscd story and the libccid allowlist
below are unaffected. This is a provisional project-local ID,
deliberately distinct from 2E8A:10FE (pico-keys, registered in
raspberrypi/usb-pid), FEFF:FCFD (pico-fido generic) and 20A0:42B2 (upstream
SDK / Clay Logic) — none of those are ours; the ID will be replaced with a
USB-IF-registered VID before production (or re-branded post-build with
picoforge).

**Persistence note:** secure-partition persist = direct QSPI program via the
embassy-rp flash driver, with power-loss durability (dual slot, format v2):

* Primary slot `0x103F0000`, shadow slot `0x103F3000` (12,288 B each =
  one image padded to 4 KiB erase sectors).
* Image format v2: magic `0x46325350` ("PS2F") + entry count +
  key/value entries + trailing CRC-32. `partition_image_is_valid()`
  rejects wrong magic, bad CRC, or out-of-bounds entry walks.
* Boot: primary is restored if valid, else the shadow, else an empty
  store (a boot-time persist rewrites both slots).
* Every persist (boot-time and lazy, after each state-changing APDU)
  programs primary then shadow; each slot is skipped when it already
  matches. Worst case = one in-flight persist rolled back to the last
  durable image — never a whole-store loss (the single-slot v1 format
  could lose all secrets on a torn write: erased primary + old code
  that validated nothing).
* CryptoCell secure-partition gating deferred post-cutover (the region
  is app-flash-reserved for now; see US-380/US-387 scope).

This layout implements the publish-after-durable discipline that the C
secure-store review (session `sess_510abb89`) found sound in
`pico-fido2`'s `flash.c` (two-phase publish, commit-before-cross-region
commit), and closes the one gap that review left open for a single-image
flash layout: torn-write total loss.

**Persistence scope note (v1.0.0):** durable state today = FIDO keystore
snapshot (`fido.keystore.v1`, includes the hkey via `fido.hkey`) and
Management `EF_DEV_CONF` + OTP slots. This became *true on device* with the
boot-store wiring fix (matrix Row 5, 2026-09-11: the stateful apps now boot
via their US-387/US-388 `boot(store)` constructors — before that fix the
apps persisted but never restored). The OATH CCID app is still constructed
fresh on every boot (`OathApp::new()`, YKOATH wiring shell, no store
restore), so row 3 lists an empty OATH set by design in v1.0.0; the FIDO HID
app is a shell (getInfo + vendor vault + error responses) whose only durable
secret is the persisted hkey.

## Matrix

Evidence captured across Phase 7 flash cycles on image `firmware/fapico2.uf2`
sha256 `be37b75c…` (commit `947000e`, S-721-5 candidate), `fa20:0002` "EddieOz"
"fapico2". Rows 1–3 are Phase 7 results (row 1 = P7-C7, on image `f8d92bd5…`
post-A2/A3; row 2 = P7-C2/P7-C3; row 3 = P7-B1); rows 4–5 re-confirmed as
regression checks during S-731-1 (Phase-7 acceptance).

**S-731-1 re-run / re-confirmation (P7-D1, 2026-09-19):** rows 2–3 re-run and
rows 4–5 re-confirmed on the **final S-723 image** `firmware/fapico2.uf2`
sha256 `f8d92bd55823…` (verified in place by `sha256sum` — no re-flash;
board `fa20:0002` "EddieOz" "fapico2", Device 091). Row 2's strict-CBOR
`get_info()` verification PASSED unrelaxed (residual note resolved); the
FIDO PIN-gated steps were blocked on hardware by a pre-existing CTAP2
`0x34 PIN_AUTH_BLOCKED` (one-probe discipline — see row 2) and defer to the
post-replug follow-up. CCID rows now carry the pyusb raw-CCID transport
substitution (`tests/scripts/ccid_usb.py`; pcscd cannot negotiate the
board). Evidence: P7-D1 transcript cycle (2026-09-19); ladder: P7-D1.

**S-731-1 re-pin (P7-D2, 2026-09-20) — the full matrix re-run on the FINAL
Phase-7 image.** The board (Device 106 → 107 after the row-5 replug) was
nuked + reflashed with the final candidate `firmware/fapico2.uf2` sha256
`53ba915e1ad405f32abfb7c2b062d2ef13d86795b557a8bab1d4aaa2eaf256f8`
(HEAD `dcf8397`, BOOTSEL file copy; factory-fresh: OpenPGP keyless, OATH
empty, FIDO PIN unset). All rows re-executed per-row below: the OpenPGP
identity was **regenerated on-card** (new fingerprint set + the full gpg
ceremony), FIDO ran PIN-free, OATH re-ran the 39-check ceremony on the
empty keystore, and rows 4–5 re-confirmed including the row-5
WRITE_CONFIG / user-power-cycle / READ_CONFIG round-trip. The P7-D1
evidence below is **superseded-by-image** (kept for the audit trail): it
was captured on the earlier S-723 image `f8d92bd5…` against a board state
that no longer exists. Two new divergence-register rows came out of this
cycle: **P7-D2-1** (U2F/CTAP1 register attestation signature fails
python-fido2 client verify — CTAP1 interop gap; CTAP2 and the soak leg
unaffected) and **P7-D2-2** (OpenPGP C4 RC-retry byte reads 0 — gpg
"PIN retry counter : 3 0 3"; nothing gated). Evidence:
P7-D2 transcript cycle (2026-09-20); ladder: P7-D2.

> **SUPERSEDED (S-393-2 review, 2026-09-11):** the v1.0.0 **shipping
> artifact** is the post-US-413 build — `firmware/fapico2.uf2` sha256
> `b9bc12f8987bdd195ab06581e3590673ed617bbfdfe01e0ba743b8b3bf7eeea1`,
> **198 blocks** (1 E10 preamble + 197 ARM_S payload), 101,376 B — which
> adds the migration code + PICOBIN partition-table embed (S-413-2…7) on
> top of the same app/identity state. Rows 1–5 evidence below was captured
> on the earlier `041addf0…` image; the `041addf0…` rows are the US-391
> evidence image, kept for the audit trail. See
> [size-report.md](size-report.md) and
> [release-notes-v1.0.0.md](release-notes-v1.0.0.md).

| # | Row | Command / method | Result | Verbatim evidence |
|---|-----|------------------|--------|-------------------|
| 1 | OpenPGP | `gpg --card-status` + `gpg --card-edit generate` + `gpg --clearsign`/`--verify` + raw APDUs (gpg 2.4.4 scdaemon **internal USB CCID driver** with pcscd stopped, pyusb raw-CCID client; AID D2 76 00 01 24 01) | **PASS — full OpenPGP command set served on device (Phase 7 S-721-1…5; P7-C7 hardware acceptance; supersedes the v1.0.0 shell scope note)** | P7-C7 (2026-09-19, image `f8d92bd5…`, post-A2/A3, HEAD `cc93704`): the full US-341 bar verified in one flash cycle on `fa20:0002` "EddieOz" "fapico2" — `gpg --card-status` ("OpenPGP card", Reader `FA20:0002:X:0`, manufacturer "test card", serial 00000000, key attrs `ed25519 cv25519 ed25519`, PIN retry counter `3 3 3`); `gpg --card-edit generate` three-key ECC **on-card generation** in the secure store (`pub ed25519 [SC]`, `sub ed25519 [A]`, `sub cv25519 [E]`, TRNG entropy) with gpg's fingerprint write-back via the 60-byte C5 DO and all three keys bound by fingerprint to `card-no: 0000 00000000`; `echo "fapico2 sign test" | gpg --clearsign` → rc 0 and `gpg --verify` → **`Good signature from "fapico2 Test <card@fapico2.local>" [ultimate]`** (twice — including after replug); PIN change (`gpg --card-edit passwd`) + one wrong probe (`63C2`, C4 pw1 = 2) + RESET RETRY COUNTER (`00 2C 02 81 06 654321` → `9000`, C4 back to 3; card never locked); GET CHALLENGE non-constant (`00 84 00 00 08` ×2 → `30 44 45 8a 0c 8d 6e 1a` / `d9 4a 7a 4a 57 03 39`); unplug/replug persistence (fprs + retries 3/3/3 + factory PW1 survive; second clearsign verifies). **Host transport fact (supersedes S-721-2's disable-ccid guidance for gpg):** pcscd cannot negotiate the board — SCardConnect T0/T1 fails `SCARD_E_PROTO_MISMATCH` (0x8010000f) on EXCLUSIVE and SHARED; the ceremony ran with pcscd stopped, gpg 2.4.4 scdaemon via its internal USB CCID driver (no `disable-ccid` in `scdaemon.conf`), and a pyusb raw-CCID client (kernel `usbhid` detached before libusb open) — pcscd and gpg/scd conflict over the USB device. Verdict doc: S-721-5 acceptance (P7-C7); transcripts retained in the local archive; ladder: P7-C7. **P7-D2 re-pin (2026-09-20, image `53ba915e…`, nuked+reflashed board, keyless start): the full ceremony re-executed verbatim (P7-C7 flow, `/tmp/p7d2` GNUPGHOME, fake-pinentry; transcript cycle P7-D2)** — preflight keyless per S-723-B3-1 (C5 = 60 zero bytes / C6 zeros / C7 `6A88`, factory caps TLV in READ_CONFIG); `gpg --card-status` → "OpenPGP card" v3.4, key attrs `ed25519 cv25519 ed25519`, **PIN retry counter `3 0 3`** (C4 `00 7f 7f 7f 03 00 03` — RC byte as-read 0, divergence **P7-D2-2**, nothing gated); `gpg --card-edit generate` three-key ECC on-card → **new identity FPR `FE11706FCB2A9AAFAA5EEA893D5EE116CD42D344`** (uid "fapico2 Test <card@fapico2.local>"), all three fprs in the 60-byte C5 DO (C5 readback `fe 11 70 6f … 7d 05`); clearsign → **Good signature** ×2, **both PRE-replug** (one post-generate, one post-PIN-restore; the replug followed later — identity persistence across it is shown by the post-replug card-status readback below, not by a second post-replug clearsign); passwd 123456→654321 ("PIN changed."), raw VERIFY old `63C2` / new `9000`, ONE wrong probe `000000` → `63C2` (C4 pw1 = 2), VERIFY PW3 → `9000`, RESET RETRY `00 2C 02 81 06 654321` → `9000` (C4 pw1 = 3, never locked), passwd restored to 123456; GET CHALLENGE ×2 non-constant (`a4 cc bb f7 96 91 b6 ac` / `01 3d 7e 2a 0c d0 ee 31`). **Post-replug (Device 107): all three fprs + cardholder + retries unchanged** (`p7d2-N-card-status-post-cycle.log`). Evidence: `tests/scripts/p7_d2_preflight.py` + `/tmp/p7d2/ceremony.sh` transcripts `p7d2-B…p7d2-J`; ladder P7-D2. |
| 1a | OpenPGP (P7-C6 draft) | — | **SUPERSEDED** — see Row 1 (P7-C7) and row 1b (P7-C6 observation, do not cite). |
| 1b | OpenPGP (P7-C6 observation — do not cite) | — | **SUPERSEDED — P7-C6 (S-723-B1 correction + P7-C7)** | P7-C6 (2026-09-18, image `be37b75c…`): SELECT AID → **SW `9000`**, FCI valid with opcard historical bytes. Key attributes readable (C1/C2/C3 = 6A88/file not found on empty card — expected). PSO:SIGN Ed25519 after PW1 verify (`00 20 00 81 06 313233343536` → `9000`) → **SW `9000` + 64-byte signature** produced successfully. PIN handling correct: correct PW1 verifies (`9000`), wrong PW1 (`000000`) → `63C2` (retries decremented), correct PW1 restores access. GET CHALLENGE (`00 84 00 00 08`) → `9000` + 8 non-constant random bytes per call. INTERNAL AUTHENTICATE returns `6982` for EdDSA keys (documented limitation — PSO:SIGN is the correct command for EdDSA signing). **Residual note:** C-migration key restore (S-721-4) committed but not exercised on this empty-card cycle; sign operation verified with freshly generated Ed25519 key. Evidence: ladder P7-C6, S-721-5 acceptance. *(Supersedes the v1.0.0 entry: "shell-limited — app present, command set not served on device…")* |

> **CORRECTION (Row 1 / P7-C6, S-723-B1, 2026-09-19) — three Row-1 claims
> are script artifacts; superseding evidence is P7-C7.** The P7-C6 ceremony
> script sent malformed GET DATA APDUs (tag in P1 instead of P2 → unknown tag
> 0xC100 → `6A88` regardless of card state, EPIC F11): the "Key attributes
> readable (C1/C2/C3 = 6A88/file not found on empty card — expected)" claim
> is a script artifact, not a card fact — and the same run's successful
> PSO:SIGN proves keys were present (F12), contradicting "empty card". The
> "freshly generated key" residual note is likewise unfounded for this cycle
> (no GENERATE was exercised; the C-migration keys from P7-C5 were what
> signed). The "INTERNAL AUTHENTICATE returns `6982` for EdDSA keys
> (documented limitation)" claim is also a script artifact (F14: INTERNAL
> AUTHENTICATE gates on the PW1 context verified with P2=0x82; the script
> had verified only P2=0x81 — under the correct context it signs, `9000` +
> 64-byte Ed25519 signature, reproduced on the emulation binary, S-723-B1
> report). Do not cite Row 1 for key-presence, empty-card, or
> INTERNAL-AUTH claims; the honest hardware re-run is **P7-C7** (S-723-B2)
> (now landed — see Row 1), which supersedes this row's OpenPGP evidence.
> This note is append-only;
> the Row-1 text above is kept verbatim for the audit trail.
| 2 | FIDO2 over HID (primary) | python-fido2 `CtapHidDevice.get_info()` (`fido2-token` NOT installable here — no distribution; python-fido2 substitution per coordinator) | **PASS — full CTAP2.1 served (Phase 7; supersedes the v1.0.0 shell scope note)** | `CtapHidDevice('/dev/hidraw7')`; `get_info()`: versions `['U2F_V2','FIDO_2_0','FIDO_2_1','FIDO_2_2','FIDO_2_3']`, aaguid `66617069-636f-3200-0000-000000000001`, maxMsgSize `7609`, options `{rk, clientPin, pinUvAuthToken, largeBlobs, credMgmt, setMinPINLength, authnrCfg, enterpriseAttestation, makeCredUvNotRqd}`. Phase-7 ceremony (P7-C2, python-fido2): setPIN ✓, PIN-permissioned token (mc|ga|cm|lbf|acfg) ✓, makeCredential rk=True + credProtect/hmac-secret (flags `0xc5` = UP|UV|AT|ED) ✓, getAssertion signature verified by python-fido2 ✓, credMgmt enumerate RPs/creds ✓, largeBlobs put+get ✓ (post-fix image), authenticatorConfig toggle alwaysUv ✓. Evidence: ladder P7-C1–P7-C3. **Residual note RESOLVED (P7-D1, S-731-1, 2026-09-19):** the strict (canonical-CBOR, unrelaxed) `get_info()` re-run on the final S-723 image `f8d92bd5…` **PASSED** — versions `['U2F_V2','FIDO_2_0','FIDO_2_1','FIDO_2_2','FIDO_2_3']`, aaguid `66617069-636f-3200-0000-000000000001`, maxMsgSize `7609`, options `{rk, clientPin, pinUvAuthToken, largeBlobs, credMgmt, setMinPINLength, authnrCfg, enterpriseAttestation, makeCredUvNotRqd}` with `alwaysUv` False (state restored) — verifying the `559d53e0` length-aware tstr sort fix on hardware with **no client-side strictness relaxation** (`tests/scripts/p7_d1_fido.py`, transcript `p7d1-C-fido-getinfo.log`). **P7-D1 PIN-gated steps NOT re-run:** the one-attempt PIN probe (`get_pin_token("1234")` — the P7-C2/C3-era PIN) returned **CTAP2 `0x34 PIN_AUTH_BLOCKED`** (pre-existing block, not a wrong-PIN `0x32`; one probe, no retries, FIDO state untouched) — and the single post-replug re-probe returned `0x34` again: the block **persists across the physical power cycle** in the firmware's FIDO state (diverges from the CTAP2.1 power-cycle-clears model) and is an open follow-up. setPIN/token, credMgmt, largeBlobs-put and authenticatorConfig hardware re-verification remain on the P7-C2/P7-C3 hardware evidence (`p7d1-D-fido-pin.log`, `p7d1-D-fido-pin-blocked-pre-cycle.log`). **P7-D2 re-pin (2026-09-20, image `53ba915e…`, nuked+reflashed board — FIDO PIN UNSET, leg designed PIN-free per brief: NO PIN ops, NO credMgmt, NO makeCredential):** strict (unrelaxed) `get_info()` **PASSED** — versions `['U2F_V2','FIDO_2_0','FIDO_2_1','FIDO_2_2','FIDO_2_3']`, aaguid `66617069-636f-3200-0000-000000000001`, maxMsgSize `7609`, options `{alwaysUv: False, authnrCfg, clientPin: False, credMgmt, enterpriseAttestation, largeBlobs, makeCredUvNotRqd, pinUvAuthToken, rk, setMinPINLength}` (`p7d2-C2-fido-getinfo.log`). U2F (CTAP1) register **succeeded on device** (key_handle 32 B, public_key 65 B, sig 71 B, cert 319 B — one store slot consumed), but python-fido2's client-side attestation `reg.verify()` raised `InvalidSignature` — recorded as divergence **P7-D2-1** (CTAP1 interop gap, first exercised here; CTAP2 paths and the soak leg unaffected); the `authenticate` leg was NOT re-run (registration data lost with the aborted script; the binding one-U2F-register-max rule forbade a corrective re-register). Row-2 re-pin verdict rests on strict get_info + register-on-device evidence (`p7d2-C3-fido-u2f.log`; script hardened to stop, never re-register, on this failure). *(Supersedes the v1.0.0 entry: "FIDO HID app is a v1.0.0 shell (getInfo + vendor vault + error responses)…")*  **US-101 (EPIC `PICOForge-COMPAT`) — AAGUID superseded:** the `66617069-636f-32…0001` AAGUID readings in this row are that run's verbatim hardware evidence and are kept unchanged for the audit trail. From US-101 onward the AAGUID is a build-time constant defaulting to the borrowed RS-Key profile `2479C7BF6B3056839EC80E8171A918B7` (so PicoForge's device-profile table selects RS-Key and offers the OpenPGP applet), overridable per build with `FAPICO2_AAGUID_HEX`. Any re-verification after US-101 should read `2479c7bf-6b30-5683-9ec8-0e8171a918b7`. See `apps/fido/src/lib.rs` and `apps/fido/build.rs`. |
| 3 | OATH (YKOATH) | CCID: OATH AID SELECT (`A0 00 00 05 27 21 01`) + the full YKOATH command set via pyscard direct APDUs — `tests/scripts/p7_b1_oath.py` (P7-B1, 2026-09-12; python-fido2 1.2.0 exposes **no** `read_oath()` — API absent in the installed release; direct-APDU substitution, same as the v1.0.0 run) | **PASS — full YKOATH command set served on device (Phase 7 S-711-1…3; supersedes the v1.0.0 "wiring shell" scope note)** | P7-B1 on the S-711-2 image `fapico2.uf2` sha256 `f3463de9…`: SELECT → **SW `9000`**, FCI `79 03 04 03 00 71 08 "fapico2!"` (YKOATH 4.3.0). 45/45 hardware checks green over real CCID (pcscd, reader `fapico2 CCID (fapico2 firmware) 00 00`): PUT/DELETE/RENAME/LIST ✓; CALCULATE TOTP full-digest vector `75 15 06 b3 99 bd fc … 30 f1` and HOTP counter vectors (ctr=0 `17 fa 2d 40`; IMF-seeded `45 d9 0f 25`/`1b c5 4a 85`) — byte-exact emulation-suite vectors ✓; CALC_ALL p2=1 (TOTP values + HOTP `77 01 06` no-response, no counter advance) ✓; OTP PIN set/verify/change (wrong PIN `6982`) ✓; SET_CODE → SELECT carries `74 08 <chal>` challenge, LIST locked `6982`, VALIDATE (HMAC-SHA1 of the SELECT challenge) → `75 14 …`, LIST unlocked ✓. **Power cycle (user USB unplug/replug):** access code + both credentials restored (LIST locked → VALIDATE → `72 05 21 "kaka" 72 05 11 "imf1"`), TOTP vector identical pre/post reboot, HOTP counter **continued** at 0xFF010001 (`76 05 06 53 1f 97 70` — matches the pre-registered prediction) ✓. Evidence: ladder P7-B1. **P7-D1 re-run (S-731-1, 2026-09-19, image `f8d92bd5…`): the full ceremony re-executed verbatim** — same APDU bytes and byte-exact suite vectors (`tests/scripts/p7_d1_oath.py`) — over **pyusb raw-CCID** (`tests/scripts/ccid_usb.py`), a transport substitution from P7-B1's pyscard/pcscd path (pcscd cannot negotiate the board, `SCARD_E_PROTO_MISMATCH` 0x8010000f, mirroring P7-C7's finding): all 39 checks PASS — SELECT → **SW `9000`**, FCI `79 03 04 03 00 71 08 "fapico2!"`; CALCULATE kaka TOTP full-digest vector `75 15 06 b3 99 bd fc … 30 f1` byte-exact; CALC_ALL p2=1 + HOTP `77 01 06` no-response; CALCULATE htop ctr=0 `17 fa 2d 40` and IMF-seeded `45 d9 0f 25`/`1b c5 4a 85` vectors byte-exact; OTP PIN set/verify/change (wrong PIN `6982`) ✓; SET_CODE → SELECT carries the `74 08` challenge, LIST locked `6982`, VALIDATE → `75 14 …`, LIST unlocked ✓. Persist-arm staged {kaka TOTP, imf1 HOTP ctr 0xFF010001, PIN 123456, access code} for the row-5 replug. **Post-replug (the same power cycle, `p7d1-I2-oath-post-cycle.log`): SELECT carries the `74 08` challenge, LIST locked `6982` (access code persisted), VALIDATE → `75 14 …` unlocks, LIST = kaka + imf1 (creds persisted), TOTP vector identical pre/post reboot, HOTP counter continued at 0xFF010001 (`76 05 06 53 1f 97 70` — matches the pre-registered prediction), VERIFY_PIN → `6985` (PIN is session state, the S-711-1 scope note), RESET cleanup → LIST empty.** Evidence: transcript `p7d1-I-oath.log`. **Residual note:** the OTP PIN record is session state in the Rust port (VERIFY_PIN after reboot → `6985`) — the `oath.keystore.v1` stream deliberately excludes it (S-711-1 scope note) where the C firmware persisted `EF_OTP_PIN`; PIN *persistence* parity is an open follow-up, PIN *ops* pass. *(Supersedes the v1.0.0 entry: "…LIST → SW `6D00` (the device OATH app is the US-386 wiring shell — commands not served)… empty set by design in v1.0.0")* **P7-D2 re-pin (2026-09-20, image `53ba915e…`, empty keystore — the ceremony provisions "kaka" itself): the full 39-check ceremony re-executed verbatim** (`tests/scripts/p7_d2_oath.py`, pyusb raw-CCID) — **39/39 PASS, 0 FAIL**: SELECT → SW `9000`, FCI `79 03 04 03 00 71 08 "fapico2!"`; lifecycle/pin/access-code phases all green with byte-exact suite vectors; persist-arm staged {kaka TOTP, imf1 HOTP ctr 0xFF010001, PIN 123456, access code}. **Post-replug (`p7d2-I2-oath-post-cycle.log`, Device 107): SELECT locked (challenge `d2 a2 dc 56 da 57 7b 74`), LIST locked `6982` (access code persisted), VALIDATE → `75 14 …` unlocks, LIST = kaka + imf1 (creds persisted), kaka TOTP vector identical pre/post reboot, HOTP counter continued at 0xFF010001 (`76 05 06 53 1f 97 70` — matches the pre-registered prediction), VERIFY_PIN → `6985` (PIN session state, S-711-1 scope note), RESET cleanup → LIST empty.** Evidence: transcript `p7d2-I-oath.log`. |
| 4 | Management capabilities | mgmt AID SELECT (`A0 00 00 05 27 47 11 17`) + READ_CONFIG (`00 1D 00 00 00`) via pyscard CCID — **re-confirmed (P7-D1) via pyusb raw-CCID** (`tests/scripts/ccid_usb.py`; pcscd cannot negotiate the board) | **PASS** (re-confirmed S-731-1) | SELECT → **SW `9000`**, data `31 2E 30 2E 30` ("1.0.0"). READ_CONFIG (no user config) → **SW `9000`**, TLV blob `1C 01 02 02 3B 02 04 01 32 33 34 04 01 01 05 03 01 00 00 03 02 02 3B 08 01 80 0A 01 00` — decode: overall len `0x1C`; TAG_USB_SUPPORTED `02 3B`; TAG_SERIAL `01 32 33 34` (8-digit flag + "234"); TAG_FORM_FACTOR `01` (YubiKey-5 class); TAG_VERSION `01 00 00`; TAG_USB_ENABLED `02 3B`; TAG_DEVICE_FLAGS `80` (eject); TAG_CONFIG_LOCK `00` (unlocked). Caps word `0x023B` = **all six capability bits** (FIDO2 `0x200`, OTP `0x01`, U2F `0x02`, OATH `0x20`, OpenPGP `0x08`, PIV `0x10`). **P7-D1 re-confirmation (S-731-1, 2026-09-19, image `f8d92bd5…`): verbatim identical** — SELECT → SW `9000`, `31 2e 30 2e 30`; READ_CONFIG → SW `9000`, the same factory caps TLV blob byte-for-byte (`tests/scripts/p7_d1_mgmt.py`, transcript `p7d1-J-mgmt-caps.log`). **P7-D2 re-pin (2026-09-20, image `53ba915e…`): verbatim identical again** — SELECT → SW `9000`, `31 2e 30 2e 30`; READ_CONFIG → SW `9000`, the same factory caps TLV `1c 01 02 02 3b 02 04 01 32 33 34 04 01 01 05 03 01 00 00 03 02 02 3b 08 01 80 0a 01 00` byte-for-byte on the nuked+reflashed board (`tests/scripts/p7_d2_mgmt.py`, transcript `p7d2-A-preflight.log` + `p7d2-J-mgmt-caps.log`). |
| 5 | Re-flash / reboot persistence | WRITE_CONFIG marker → **user power cycle (USB unplug/replug — no programmatic reboot in Rust)** → READ_CONFIG | **PASS after the boot-store wiring fix** (re-confirmed S-731-1 on the final S-723 image: WRITE + power cycle + READ verbatim) | Marker `F4 1C 0F 02 11 02 EA`: WRITE_CONFIG → SW `9000`; pre-cycle READ_CONFIG → `07 F4 1C 0F 02 11 02 EA` (1-byte length + blob verbatim); **user power cycle** 2026-09-11T10:18:39Z (board re-enumerated as Device 057, fresh boot) → READ_CONFIG → **`07 F4 1C 0F 02 11 02 EA` verbatim — PASS**. **First run (E10) FAILED**: the marker persisted to flash (verified in-situ by the E11/E12 flashdiag cycles: primary slot held a valid format-v2 image, 2 entries, marker present) but READ_CONFIG after the reboot returned the factory caps blob — root cause: `main.rs` constructed the stateful apps with `new()` (factory state) instead of `boot(store)`, so the app never loaded the persisted blob. Fixed by wiring `FidoApp::boot` / `ManagementApp::boot` / `OtpApp::boot` (US-387/US-388); re-run above PASSES, and the pre-fix E10-era marker was restored from flash with **no write** as immediate confirmation (ladder E13). **P7-D1 phase 1 (S-731-1, 2026-09-19, image `f8d92bd5…`):** pre-write READ_CONFIG returned the factory caps blob; WRITE_CONFIG (`00 1C 00 00 08 07 F4 1C 0F 02 11 02 EA` — the stored blob carries its own 1-byte length prefix, per the US-413 C-side record) → **SW `9000`**; pre-cycle READ_CONFIG → **`07 f4 1c 0f 02 11 02 ea` verbatim — MATCH** (`p7d1-K-write-config-pre-cycle.log`; a first 7-byte attempt returned SW `6700` wrong-length — host framing, no state change, READ_CONFIG re-verified the factory blob before the single corrective attempt). **Physical replug staged — phase 2 executed (2026-09-19, board re-enumerated as Device 092, fresh boot, `fa20:0002`): READ_CONFIG → SW `9000`, `07 f4 1c 0f 02 11 02 ea` verbatim — ROW 5 RE-CONFIRMED PASS on the final S-723 image** (`p7d1-M-readconfig-post-cycle.log`, `p7d1-L-replug-lsusb.log`; a first SELECT-less READ_CONFIG attempt returned `6A82` — no app selected in the fresh session, sequence omission recorded verbatim). The same replug's OATH-side persistence corroboration is in row 3 (`p7d1-I2-oath-post-cycle.log`). **P7-D2 re-pin (2026-09-20, image `53ba915e…`):** pre-write READ_CONFIG returned the factory caps blob (nuked board, no prior marker — `p7d2-A-preflight.log`); WRITE_CONFIG (`00 1C 00 00 08 07 F4 1C 0F 02 11 02 EA`, the 07-prefixed 8-byte form) → **SW `9000` on the first attempt**; pre-cycle READ_CONFIG → **`07 f4 1c 0f 02 11 02 ea` verbatim — MATCH** (`p7d2-K-write-config-pre-cycle.log`); **user power cycle (Device 106 → 107, fresh boot): SELECT mgmt AID first, then READ_CONFIG → SW `9000`, `07 f4 1c 0f 02 11 02 ea` verbatim — ROW 5 RE-PINNED PASS on the final image** (`tests/scripts/p7_d2_replug.py`, `p7d2-M-readconfig-post-cycle.log`, `p7d2-L-replug-lsusb.log`). The same replug's identity-persistence corroboration is in rows 1 (`p7d2-N-card-status-post-cycle.log`) and 3 (`p7d2-I2-oath-post-cycle.log`). |
| 6 | PIV | — | **DEFERRED** | PIV is out of v1.0.0 scope (EPIC: PIV-init excluded, see CI pytest-gate notes); `yubico-piv-tool` row intentionally not run. |

## Flash-attempt history (single-boot discipline)

| Attempt | Image | Outcome |
|---------|-------|---------|
| TEST 1 | Rust UF2, no E10 abs preamble | Bootrom rejected: board stayed in BOOTSEL after reset. |
| TEST 2 | Rust UF2, family-id fix only | Same: stayed in BOOTSEL. |
| TEST 3 | Rust UF2, E10 abs block present, **no sector padding** | Same: stayed in BOOTSEL. Root cause then open. |
| Control | Known-good C image `pico_fido2_pico2-1.0.uf2` (20a0:42b2 "Pol Henarejos"/"Pico Key") | Booted in ~1 s — board healthy (has rescue app, so `scripts/bootsel.py` works while it runs). |
| DBG-1 | Rust UF2, E10 preamble + sector padding + FA20:0002, 165 blocks | Flashed; **silent boot** — dark, no USB enumeration. Root cause then open. |
| DBG bisect | dbg2 staged-LED diagnostic images (LED blink groups + self-identifying fault/IRQ traps on GPIO25) | Localized the halt: boot frames dipping below the MSPLIM the bootrom leaves set at image hand-off → STKOF → trap re-fault → lockup. Verified: small-frame variants boot, 18 KiB-frame variants die (without the clamp). The MSPLIM clamp below fixes it; dbg2 traps/stages removed from the final image. |
| Final (US-391 evidence image — **superseded as shipping artifact**, see header note) | Shipping image `firmware/fapico2.uf2` sha256 `041addf099be3347dbd1a7d6d0bb1d2e2714837b2d3b650f740cfaf16ede529c`, 133 blocks (1 absolute preamble + 132 ARM_S payload), 68,096 B; FA20:0002; boot-store wiring fix (Row 5); dbg2 removed | **EXECUTED 2026-09-11** — flash + `lsusb` verified (`fa20:0002` "EddieOz" "fapico2", Device 056/057) + rows 1–5 recorded above; row 1/3 shell-limited with scope notes, row 6 DEFERRED. Supersedes the earlier `81d1a42f…` candidate (which carried the Row-5 app-boot wiring defect). The v1.0.0 shipping artifact is `b9bc12f8…` (198 blocks, post-US-413) — see the header note. |

Boot-failure root cause 1 (fixed in `firmware/uf2gen.py`): the RP2350
bootrom erratum RP2350-E10 requires the picotool "absolute block" preamble
(flags 0xA000, target 0x10FFFF00, family 0xE48BFF57, extension word
0x9957E304) on every RP2350 UF2, plus 4 KiB erase-sector page coverage for
every touched sector (picotool's sector padding; the bootrom uses block
numbers for erase-sector calculations, pico-bootrom `virtual_disk.c`).

Boot-failure root cause 2 (fixed in `firmware/src/main.rs`, the DBG-1
silent boot): the RP2350 bootrom leaves **MSPLIM** set at image hand-off
(the C SDK's crt0 relies on that — crt0.S: "SP (and MSPLIM) on Armv8-M
should already be set"). The async boot path legitimately holds
multi-KiB stack frames (by-value secure-partition reads) in the 520 K
SRAM; a frame dipping below the bootrom's limit faults with STKOF, the
fault trap's own stack push re-faults, and the core locks up completely
dark. The firmware's first act clamps MSPLIM to the SRAM bottom before
anything else runs, and keeps a clean-slate NVIC mask+clear loop (bound
drivers re-enable their own IRQs).

> **SUPERSEDED (2026-09-10, boot ladder E2b/E6–E8) — kept as history.** The
> MSPLIM theory above was refuted: the E2b reset-vector discriminator proved
> the bootrom honors VT[1] and the entry path was never the fault, and
> cortex-m-rt's `set-msplim` was active in every disassembly while images
> still died. The dbg2 bisect narrative above is likewise superseded — the
> "dark LED" observations it rests on were an instrumentation artifact (the
> raw-SIO `dbg_blink` markers never lit the LED; only the embassy `Output`
> path does — E6b/E6c retraction in the ladder doc). The reconciled root
> cause is the **task-frame overflow chain** — see the boot bring-up section
> below (the per-cycle boot evidence log is retained in the local archive).
> The MSPLIM clamp and NVIC clean-slate code were stripped from the shipping
> image in S-391-13 and are unnecessary.

## Identity verification after boot

`lsusb` must show `fa20:0002` "fapico2`.

The manufacturer is **"The BLOCO Community"** for any image built from the
current `firmware/boards/pico2.toml`; that is what
`check_release_notes.py` now holds the release notes to, so the two cannot
drift apart silently again.

"EddieOz" was the manufacturer before the 2026-09-28 rename, and it still
appears in the rows above because those runs predate it. **A run that flashes
a current image and records "EddieOz" is a defect, not a legacy exception** —
it means the image on the board is older than the tree it was flashed from.
Recording which string was actually seen is the point of this check; do not
normalise the old one away.

If 20a0/42b2 still shows, the Rust image is not what booted — the run stops
and is reported.

## Cross-check against the C secure-store / TRNG review (sess_510abb89)

The C review of `pico-fido2` (FIDO2 + OpenPGP/PIV firmware, C) was used as
the threat model for this Rust implementation. Disposition of each finding
class in `fapico2`:

* **TRNG — clean in the C review, clean here by construction.** The C
  `hwrng.c`/`random.c` (HW TRNG + xoroshiro ring) was byte-identical to
  the SDK pin and its design judged sound. The Rust device uses the RP2350
  hardware TRNG as the **sole** randomness source (`Rp2350Trng`, US-380),
  with a CI grep gate (no `#[global_allocator]`, no std heap on the
  device) so no software RNG can be introduced.
* **Cross-app wipe / FID-alias bugs — structurally absent.** The C bugs
  (FIDO `authenticatorReset` wiping the shared vault container; OpenPGP
  TERMINATE DF wiping the FIDO app; `EF_META` 0xE010 double-ownership
  where PIV meta is silently wiped while FIDO returns OK; a shared
  0x0002 vault namespace whose per-family WRAP roots make unenroll fail
  when FIDO + OpenPGP/PIV coexist — the 100/100 finding) all stem from a
  shared file-ID table where one app's delete op reaches another app's
  data. `fapico2` has **no shared FID table**: every app owns named
  key slots in the `SecureStore` (`fido.keystore.v1`, `fido.hkey`, the
  Management `EF_DEV_CONF` slot, the OTP slot) and the trait exposes no
  whole-store wipe — `FidoApp` CTAP2 authenticatorReset clears only its
  own keystore snapshot, Management INS_RESET clears only Management
  config, OATH reset clears only OATH state. A whole-store loss is
  reachable only by a corrupt image, which the format-v2 validation
  converts into a fresh boot, not a cross-app clobber.
* **Power-loss durability — the one actionable gap, now implemented.**
  The C `flash.c` publish-after-durable discipline (two-phase publish,
  commit before cross-region commit, all-or-nothing validate, root
  zeroize on every exit, honest errors instead of OOM crashes) is the bar.
  `fapico2`'s single-slot v1 layout could not meet it (torn erase+program
  → invalid image → empty store → silent hkey re-derivation → orphaned
  credentials); the dual-slot format-v2 layout above does: worst case is
  one in-flight persist rolled back.
* **Half-provisioning (score-0 residual: key stored, cert EF empty, no
  retry) — carried as a PIV design constraint** in
  `docs/tasks/piv-us374-wip/README.md` for when the PIV app resumes:
  check key-generation/certification results **before** storing, and keep
  a provisioning retry while the key EF is empty.

## Boot bring-up — the reconciled final story (US-391, 2026-09-11)

This section is the post-bring-up narrative. The per-cycle boot evidence
log it summarizes is retained in the local archive. `docs/tasks/us391-boot-debug-notes.md` is
committed as history; its MSPLIM theory is superseded and marked there.

**Root cause of the dark boots — a task-frame overflow chain, three links
long.** The executor wedged before `main()`'s first statement whenever large
objects rode an async frame:

1. **Store in the async `main()` frame** (~9 KB `Rp2350SecureStore`):
   bring-up 2b (store in-frame) was DARK, 2c (`static mut STORE`) booted —
   the decisive flip. MSPLIM was exonerated in the same pass: cortex-m-rt's
   `set-msplim` was active in the disassembly and images still died.
2. **Store copied by value into the `ccid_task` spawn param** (E3/E4 dark;
   E5, store by reference + a 64 KB task arena, booted and enumerated but
   wedged before the executor reached the serve loops).
3. **App objects + `Dispatcher<4>` in the `ccid_task` future** (E5's
   remaining (b)-class wedge): E6 moved all four CCID apps and the
   dispatcher into the same write-once `static mut` slot pattern; the task
   future shrank to the E2-bridge shape and the full app stack has booted
   and served ever since (E6→E13, eight consecutive boots).

**Entry path:** the bootrom **honors VT[1]** — proven by the E2b
reset-vector discriminator (a distinctive blink handler wired to VT[1]
blinks; the "bootrom jumps to the start of `.text`" claim is refuted).
`uf2gen.py`'s canonical VT[1]→`Reset` patch is therefore load-bearing, not a
no-op. The E10-erratum absolute preamble + 4 KiB sector padding (root cause
1 above) remain required for every RP2350 UF2.

**Retired artifacts / invalidated evidence:** V8 (`v8-fullapp-msplim-fix`)
and V9 (`v9-frame-control`) are retired; the dbg2-4 "darkness" observations
are invalidated (the raw-SIO LED markers never lit — instrumentation
artifact, E6b/E6c retraction); the MSPLIM-clamp and clean-slate-NVIC code
was stripped in S-391-13; the superseded root-cause-2 narrative above is
kept marked.

**Found by the matrix itself (E10→E13):** Row 5 exposed a genuine wiring
defect the whole bring-up ladder had sailed past — the stateful apps were
constructed with factory constructors (`new()`) instead of their
US-387/US-388 `boot(store)` constructors, so nothing persisted was ever
*loaded* back: WRITE_CONFIG's marker was correctly persisted to the
dual-slot flash image (proven in situ by the E11/E12 flashdiag cycles) yet
every reboot booted factory state. Fixed by wiring
`FidoApp::boot`/`ManagementApp::boot`/`OtpApp::boot` (a failed FIDO keystore
boot is fatal per US-387); Row 5 then passed, including restoring the
pre-fix marker from flash with no write. Lesson recorded: persistence needs
both halves — persist *and* restore — and the restore half had no on-device
coverage until this matrix ran.

**USB identity evidence (final):** `Bus 001 Device 057: ID fa20:0002
EddieOz fapico2` — evidence image `041addf0…`, 133 blocks (the v1.0.0
shipping artifact is the post-US-413 `b9bc12f8…`, 198 blocks — header note).
Host note: the provisional `0xFA20` VID must be added to libccid's
`Info.plist` allowlist before pcscd claims the CCID interface (no wildcard
in the list; see README Requirements).

*C-image identity note (S-393-2 review):* the matrix control row records
`20a0:42b2 "Pol Henarejos"/"Pico Key"` (the local debug C build) while
`docs/tasks/us413-hardware-e2e.md` records `20a0:42b2 "Clay Logic" "Pico
Key"` (the C release build `pico_fido2_pico2-1.0.uf2`) — both are verbatim
`lsusb` observations of different C builds; the release build carries the
Clay Logic strings.
