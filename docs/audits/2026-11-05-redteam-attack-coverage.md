# Attack-coverage matrix — hardware-wallet & security-token attack classes vs. the fapico2 red-team suite

**Date:** 2026-11-05 · **Attacker model** (inherited from round 3): USB access,
no PIN, no lab equipment (no EM probe / fault rig / SWD). Classes that need lab
equipment are listed but marked out of scope rather than silently omitted.

Coverage keys: **S** = covered by a script that asserts a verdict ·
**P** = covered by a probe (prints, no verdict) · **H** = hardware-leg only ·
**—** = gap (no coverage; a proposed proof names the leg).

## 1 · CTAP2 protocol-level

| Attack class | Known instances | Suite coverage | Proof status |
|---|---|---|---|
| pinUvAuth protocol downgrade (v1 lacks domain separation; Barbosa et al., ePrint 2025/459; cf. YSA-2025-02 shape-validation flaw in protocol 2) | F8 in ROUND3 | `ctap2_probe.py` P (getKeyAgreement p=1/2), `ctap2_probe.py` (setPIN no-auth) | **New: `tests/harness/test_redteam_round3.py::test_f8_pin_uv_auth_protocol_1`** — asserts getInfo advertises `[1,2]` and p=1 handshake is accepted (F8 open → the test is the regression tripwire when v1 is dropped) |
| pinUvAuthToken permission-bit confusion (RP / CM / GA / mcGA / plA / bw) | CTAP 2.1 §6.5.5 | `fido_malleability.py` §4 floods tokenless; no token-with-wrong-permission matrix | **—** gap: token minted for GA used on credMgmt (and vice versa) must answer `0x27`; needs a PIN-set emulator leg |
| Destructive command without consent (`authenticatorReset`) | R2-14 / F1, **FIXED** | `reset_presence_gate.rs` (host twins) + `test_redteam.py` legacy | S (regression) |
| Credential enumeration without token | CTAP 2.1 credMgmt | `fido_malleability.py` §4 (all 17 subcommands), `ctap2_probe.py` | P — upgrade to assert bounded errors + no metadata leak (S) |
| `largeBlobs` abuse (unauth write, huge offsets) | CTAP 2.1 §6.10 | `hid_fuzz.py` §4, `fido_malleability.py` §4 | P |
| Flag reflection / `alwaysUv` lie / `up=false` acceptance | NDSS-class attack 6 (Yadav et al., NDSS 2024; CTRAPS arXiv 2412.02349) | `fido_malleability.py` §2/§3 (up/uv coercion), AGENTS.md §4 advertisement rules | P + host tests (`uv.rs`, `make_cred_uv_not_rqd.rs`) — S on the advertisement half |
| Clone detection / signature-counter monotonicity | NDSS-class attack 7 | **—** (round 3: "needs a credential and a real assertion") | gap: emulator leg — register, assert, roll the counter, assert again, check rejection |
| Enterprise attestation / `setMinPINLength` abuse | CTAP 2.1 §6.1/§6.5 | **—** | gap: `authenticatorConfig` subcommand matrix with a valid token |

## 2 · CTAPHID transport

| Attack class | Known instances | Suite coverage | Proof status |
|---|---|---|---|
| INIT flood / CID exhaustion / CID reuse | Google CTAP2-test-tool fuzzing corpus | `hid_fuzz.py` §1 (60 INITs, monotonic CIDs) | P |
| Framing abuse (BCNT 0xFFFF, reserved CID 0, bridge CID, broadcast non-INIT, seq bits) | CTAPHID spec violations | `hid_fuzz.py` §3, `hid_framing.py` | P |
| Multi-frame reassembly + INIT preemption race | US-705.1 exemption | `hid_reassembly.py`, `hid_framing.py` §race | P |
| Hostile CBOR (0x1B 64-bit heads, nesting, indefinite lengths, duplicate keys) | §6 getInfo width rule | `hid_fuzz.py` §4, `getinfo.rs` host gate | P + S (host) |
| Transaction timeout / CANCEL handling / keepalive window | FX-402 keepalives | `test_keepalive_window.py` | S (emulator) |

## 3 · CCID applets

| Attack class | Known instances | Suite coverage | Proof status |
|---|---|---|---|
| OATH default/derived access code → full takeover (VALIDATE → LIST → CALC → PUT seed poisoning); YKOATH has **no retry counter** by design, and this firmware's SELECT publishes the PBKDF2 salt unconditionally | F4; YKOATH protocol docs; community-documented unlimited OATH-password guessing on YubiKeys | `oath_exploit.py` P (and **broken** — A1 in [2026-11-05-redteam-quality-audit.md](2026-11-05-redteam-quality-audit.md)), `test_redteam.py::_authenticate` (correct dialect, owner-side only) | **New: `test_redteam_round3.py::test_f4_default_access_code_takeover`** — end-to-end exploit asserted on the emulator. Remaining gap: `oath_guess_budget.py` (measure that VALIDATE really has no rate limit / lockout) — proposed, hardware leg |
| YubiOTP slot framing abuse (10-chunk YK4, known-secret configure, `0x80|slot` write form) | `otp_exploit.py` | P — was executed live in round 3; refused; keep as P with verdict |
| OpenPGP invalid-curve / small-order point PSO:DECIPHER oracle | CVE-2019-9155 shape; SandboxAQ invalid-curve class | `pgp_malleability.py` P — **tautological as written** (T2: no valid-input canary) | gap: rewrite with an opened PW1 session + valid canary before the mutation sweep |
| OpenPGP algorithm confusion (PSO:CDS P2 variants, digest lengths) | minerva/algorithm-confusion class | `pgp_malleability.py` §B | P |
| OpenPGP CLA handling (unassigned class → 9000) | F10 | **—** (round-3 evidence only, inline in report) | gap: `f10_cla90.py` — cheap hardware leg: `90 A4` vs `00 A4` SW comparison; emulator leg blocked by opcard client wiring, revisit when opcard is host-runnable |
| PIV applet attacks | none published for this applet here | **—** (`ccid.py` defines `PIV_AID`; no script uses it) | gap: `piv_probe.py` (SELECT, PAYMENT token probes, unauth PUT DATA) |
| Management `INS_MIGRATION` distinguishable-status oracle | F6 | **—** automated; hardware evidence only (host builds answer `INS_NOT_SUPPORTED` by construction) | gap: hardware leg `f6_migration_oracle.py` with verdict; emulator leg impossible until the handler is host-wired |
| Rescue REBOOT (enumeration DoS, BOOTSEL replacement) | F5 / F7 | `reboot_retry.py` P | P — add verdict; BOOTSEL-extraction remains accepted-by-design (F7) |
| Cross-applet AID confusion (overlap, prefix direction) | AGENTS.md §7 | `apps/tests/registry.rs` S (host) | S |

## 4 · Host-observable side channels

| Attack class | Known instances | Suite coverage | Proof status |
|---|---|---|---|
| PIN-verify timing (early exit / length leak) | Minerva-class | `timing.py` — **tautological** (T1: ECDH dominates, 3 samples, conclusion pre-written) | gap: redesign (differential, ≥30 samples, verify-stage isolation) or retitle inconclusive |
| Deterministic-encryption activity oracle (getInfo `encCredStoreState`) | F3, **FIXED** | `scripts/verify_getinfo_oracle.py` S + remediation record hardware table | S |
| Retry-counter persistence (replug brute force) | stock-YubiKey class | `reboot_retry.py`, `pin_recover.py` (rewritten as a verdict probe) | P — verdicts added |
| Response-length / error-class distinguishability | generic oracle class | `pgp_malleability.py` verdict, F6 status bytes | partial |

## 5 · Out of scope by attacker model (recorded, not tested)

- **EM side-channel key extraction** (EUCLEAK, ePrint 2024/1380; CVE-2024-45678
  Infineon lib) — needs an EM probe station and ~24 h of traces. Recorded as
  the standing limitation of "the key cannot leave the chip" (round 3 §Limits).
- **Fault injection / glitching** (voltage/clock; Trezor-class bootloader
  glitches) — needs a rig.
- **BIP-39 mnemonic-entry SCA** (CVE-2025-69893 shape) — this device has no
  mnemonic-entry UI.

## 6 · Supply chain / flashing

| Attack class | Suite coverage | Proof status |
|---|---|---|
| Unauthenticated UF2 replacement via REBOOT→BOOTSEL | F7 accepted-by-design, `reboot_retry.py` reach | P |
| Firmware image extraction (flash dump) + at-rest seal | F7 (4 MiB dump, OTP `0xE90` refused, 7.87 bits/byte store) | H, executed round 3 |
| Capture-build surfaces (`apdu-trace`, fixed-then-random drain CID) | F9, US-922 per-boot CID | S (unit) + release-gate script `scripts/check_release_debug_state.sh` |
| Debug interface open (SWD key extraction precondition) | F2, ADR 0002 release gate | S (gate script) — hardware re-verify owed at first `-release` tag |

## Sources

- Yadav et al., *A Security and Usability Analysis of Local Attacks Against
  FIDO2*, NDSS 2024 — clone detection, local FIDO2 attack classes.
- Berladskyy & Assmuth, *An Analysis of Attack Vectors Against FIDO2
  Authentication* (arXiv 2604.20826) — seven attacks incl. attacker-known-key
  generation and clone-detection bypass.
- *CTRAPS: CTAP Client Impersonation and API Confusion on FIDO2* (arXiv
  2412.02349) — eight CTAP-spec vulnerabilities.
- NinjaLab, *EUCLEAK* (ePrint 2024/1380) — EM side-channel ECDSA recovery on
  YubiKey 5 (<5.7).
- Yubico YSA-2025-02 / CVE-2025-29991 — CTAP PIN/UV auth protocol 2
  length-validation flaw.
- YKOATH protocol spec (developers.yubico.com/OATH/YKOATH_Protocol.html) —
  VALIDATE direction, access-code derivation, no retry counter.
- Google CTAP2-test-tool fuzzing docs — transport fuzz corpus shape.
- [List of Hardware Wallet Hacks](https://thecharlatan.ch/List-Of-Hardware-Wallet-Hacks),
  [DarkNavy lost-wallet analysis](https://www.darknavy.org/blog/if_the_person_who_finds_a_web3_hardware_wallet_is_a_hacker) —
  supply-chain / firmware-replacement taxonomies.
