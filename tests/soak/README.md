# 24-h soak (US-385)

Prove the merged firmware is **panic-free** over a long, unattended run —
stability that is *measured*, not assumed. A single panic (or a hung USB
channel) on a shipped key means a dead authenticator in a user's pocket; the
soak finds that on the bench before release.

**Pass criterion: zero panics over the soak window.** A *wrong status word* is
deliberately **not** a soak failure — functional correctness is the pytest
gate's job (see `run_all_tests.sh` / the CI `pytest-gate`). The soak isolates
the stability property: does the dispatcher + app code survive a long, mixed
session mix without panicking or hanging?

## The defmt panic counter (device side)

`firmware/src/main.rs` installs a `#[panic_handler]` that increments a
monotonic `static` counter and emits it over defmt/RTT before hanging:

```rust
static SOAK_PANIC_COUNT: AtomicU32 = AtomicU32::new(0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let n = SOAK_PANIC_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    defmt::error!("SOAK-PANIC #{}", n);
    loop {}
}
```

On bench hardware the soak driver decodes the firmware's defmt config with
`probe-rs defmt` and counts the `SOAK-PANIC #N` lines in the RTT stream
(`soak.py`'s `RttPanicWatcher`). A panic also leaves the USB stack hung, which
the driver independently sees as the device going unresponsive. (On the
host/emulation build the equivalent detector is simpler — a panic aborts the
`fapico2-emulation` process and writes a `panicked at` line to its log, which
`soak.py`'s `EmuPanicWatcher` reads alongside the process liveness check.)

## One cycle — interleaved app sessions

Each loop iteration drives the same mixed session a real user generates (a
browser doing webauthn on HID while gpg/scdaemon holds the CCID channel),
exercising the AID dispatcher's app-switching logic — the code path most prone
to a stuck-session or cross-app bug:

| # | Transport | App | Operation |
|---|-----------|-----|-----------|
| 1 | CCID | OpenPGP | `SELECT` AID `D276…2401`; `SELECT` MF |
| 2 | HID  | FIDO2   | CTAP2.1 `get_info` (proves FIDO alive on its own transport while CCID is free) |
| 3 | CCID | OATH    | `SELECT` AID `A000…2101` |
| 4 | CCID | mgmt    | `SELECT` AID `A000…17`; `READ_CONFIG` (caps TLV) |

PIV is excluded — it is not implemented and is out of scope per the EPIC.

## Running

```sh
cd fapico2/tests/soak

# 24-h emu soak (default) — no hardware; drives fapico2-emulation over TCP.
./run_soak.sh

# Short verification run (CI / "does the harness work").
./run_soak.sh --max-cycles 200

# 24-h bench run on real RP2350 hardware.
./run_soak.sh --transport usb \
    --firmware-elf ../../target/thumbv8m.main-none-eabi/release/fapico2-firmware
```

`run_soak.sh` builds the emulator (emu transport) if missing, frees any
*orphaned* leaked emulator from a prior run (the TCP ports 35962/35963 are
hardcoded, so a leak blocks the next soak), then runs `soak.py` and reports.

### Transports

* **`emu` (default, verified).** Drives the `fapico2-emulation` binary — the
  *same* Rust dispatcher + app crates, just over the TCP CCID/HID sockets the
  emulation build exposes instead of USB. This is the transport that runs in
  CI and on a dev box; it proves the dispatcher/app logic is panic-free and
  that the harness (loop, detection, archiving) works end-to-end.
* **`usb` (bench hardware).** The identical cycle over a real RP2350: pyscard
  for the CCID smartcard, fido2's native HID for FIDO2, and `probe-rs defmt`
  for the panic counter. Requires the device flashed with the release ELF,
  `pip install pyscard`, and `cargo install probe-rs`. This is the release
  engineer's 24-h bench step; it shares all cycle/detection logic with the
  verified emu path.

## Reading the result

Every run archives under `--log-dir` (default `logs/soak-<UTC-stamp>/`):

* `soak_cycles.log` — one line per operation (timestamp, cycle, app, op, SW).
* `emulator.log` (emu) / `rtt.log` (usb) — the device's own output; a panic is
  visible here as `panicked at` (emu) or `SOAK-PANIC #N` (usb).
* `soak_summary.txt` — verdict, transport, window, cycle count, panic count, exit code.

**Exit code / verdict:**

* `0` — **PASS**: the window completed with zero panics.
* `1` — **FAIL**: a panic was detected (the device hung / process aborted).
  The first `PANIC`/`DEAD` line in `soak_cycles.log` marks the cycle; the
  device log shows the panic backtrace.
* `2` — **harness/setup error**: the emulator/device couldn't be started (port
  in use, binary missing, no reader, no `probe-rs`), so no soak actually ran.

A `2` is *not* a pass — it means the soak could not run and must be re-run
before release sign-off.
