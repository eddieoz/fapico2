# Threat model

fapico2 runs on a $5 general-purpose microcontroller, not a secure element. The keys live in flash sealed under a root key derived from one-time-programmable (OTP) memory. That is the honest baseline, and here is what it means.

## What is and is not possible

- **No remote attack.** The device build has no network stack. Everything on this page requires **physical access to the chip**.
- **A flash dump alone opens nothing.** The store key is not in flash — it is derived from a one-way-fused OTP row plus the chip's identity. An attacker with a dump has ciphertext and no key.
- **Recovering the root key from the chip itself is possible — with a lab.** The RP2350's OTP and boot path were broken in [Raspberry Pi's own hacking challenge](https://www.raspberrypi.com/news/security-through-transparency-rp2350-hacking-challenge-results-are-in/), by fault injection and semiconductor failure-analysis techniques. It can be done. It needs physical possession, specialised equipment, and in the hardest cases a decapsulated die under a laser or a focused ion beam.
- **The easiest way in is none of the above.** Until the first release tag, the debug port is open on every published image — a debug probe and brief physical access extract every key the device holds, no lab required. That is the boundary the first `-release` tag closes.

## The actual attacks (RP2350 hacking challenge, January 2025)

Raspberry Pi offered a $20,000 prize to the first person to extract a secret value from RP2350's OTP memory. Four valid submissions won, plus a fifth found outside the contest. Every one of them attacks the chip itself — the boot path and the OTP — not the firmware, so every RP2350 board is exposed to them, ours included. In easy terms:

| Attack | How it works | Equipment | Mitigated |
|---|---|---|---|
| **"Hazardous threes"** (erratum E16) | Drop the OTP power pin at exactly the right moment and the chip reads a known filler value back as its security configuration — debug turns on, and the OTP then reads out | A power-supply rig and good timing | **No** — no mitigation in current silicon |
| **Boot-ROM reboot fault** (E20) | Voltage glitching skips one instruction in the boot ROM; the chip reboots to an attacker-chosen address and runs unsigned code already preloaded in RAM, which dumps the OTP | A bench-top voltage-glitch rig | **Yes** — an OTP flag disables the abused reboot mode |
| **Signature-check fault** (E24) | A precisely timed fault makes the signature check hash attacker-controlled data instead of the firmware — an unsigned image passes and runs | A custom laser fault-injection setup, die decapsulated by grinding | **No** — no mitigation in current silicon |
| **Antifuse readout** (IOActive) | A focused ion beam with passive voltage contrast — a standard semiconductor failure-analysis technique — reads the OTP storage bits directly, adjacent cells two at a time | A semiconductor failure-analysis lab (FIB workstation) | **Partially** — the current form cannot separate paired bits; chaffed storage is the recommended defence |
| **OTP permission bypass** (E21) | Electromagnetic fault injection disturbs two instructions at once, preventing the OTP from being locked down before BOOTSEL — OTP read/write through the USB bootloader even when the configuration forbids it | An electromagnetic fault-injection setup | **Yes** — OTP flags disable the USB bootloader's OTP access |

Two of the five have no mitigation at all in current silicon; the chip is expected to be hardened in a future stepping.

## What this means for fapico2

- **Every attack needs the board in hand** and equipment that costs orders of magnitude more than the board does. A remote attacker gets nothing: there is no network stack.
- **The attack within anyone's reach — a plain flash dump — is what the store design stops.** The store key is derived, not stored; ciphertext without the root key is inert. The store key is hashed from the OTP row, which stops a flash-dump attacker; it does not stop an attacker who can read the OTP bits themselves — that is what the lab-level attacks are for.
- **Signed secure boot raises the bar, not the ceiling.** It is opt-in (`./build-signed.sh`), one-way, and it makes two of the five attacks harder to reach — it does not make the chip a secure element.

Read [Raspberry Pi's full write-up](https://www.raspberrypi.com/news/security-through-transparency-rp2350-hacking-challenge-results-are-in/) — the findings are more useful than the reassurance would be.
