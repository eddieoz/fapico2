//! RP2350 emulator harness for debugging the fapico2 firmware boot.
//!
//! Loads the real `fapico2-firmware` ELF into the rp2350-emu flash, boots the
//! RP2350 bootrom, and traces execution from reset until it either reaches
//! main(), faults, or hits a watchdog/loop. This runs the *actual* firmware
//! binary — not a re-implementation — so it pinpoints the true boot-crash site.
//!
//! Usage:
//!   cargo run -p fapico2-emu-harness -- <firmware.elf> [--trace] [--max-cycles N]
//!
//! The firmware ELF is normally at:
//!   ../../target/thumbv8m.main-none-eabi/release/fapico2-firmware

use clap::Parser;
use rp2350_emu::{Arch, Config, Emulator, EmulatorBuilder};

use std::path::PathBuf;

const FLASH_BASE: u32 = 0x1000_0000;

#[derive(Parser)]
#[command(name = "fapico2-emu-harness", about = "RP2350 emulator boot debugger")]
struct Args {
    /// Path to the firmware ELF binary
    firmware: PathBuf,

    /// Trace every instruction (PC/SP/MSPLIM) — very verbose
    #[arg(long)]
    trace: bool,

    /// Maximum cycles to run before giving up
    #[arg(long, default_value_t = 50_000_000)]
    max_cycles: u64,

    /// Stop when PC reaches this address (e.g. the Reset handler)
    #[arg(long, value_parser = parse_addr)]
    stop_at: Option<u32>,

    /// Skip the bootrom: set PC/SP directly from the firmware vector table.
    /// This isolates the firmware boot path (Reset handler → main) from the
    /// bootrom's IMAGE_DEF scan. Use this to debug dark-boot.
    #[arg(long)]
    no_bootrom: bool,

    /// Skip __pre_init: when PC reaches 0x10001000, jump to 0x1000020a.
    /// The emulator doesn't implement the PLL_USB peripheral that
    /// __pre_init touches, so it faults there. This lets us debug the
    /// firmware boot path past that point. Requires --no-bootrom.
    #[arg(long)]
    skip_pre_init: bool,

    /// Skip .bss/.data clearing: when PC is in the Reset handler's
    /// zero-init loop (0x10000210..0x10000216), fast-forward r0 to r1 to
    /// force the loop to exit. The emulator clears .bss very slowly, so
    /// this gets us to main() faster. Requires --no-bootrom.
    #[arg(long)]
    skip_bss: bool,

    /// Bulk-copy the .data init image and exit the Reset handler's copy
    /// loop (0x1000021e..0x10000226): on first PC hit, read r0/r1/r2
    /// (RAM start / RAM end / flash source), copy the whole image via
    /// debug peek/poke, then set r0=r1. The emulator's XIP flash reads
    /// are extremely slow and .data is ~65 KB — without this, boot
    /// never reaches main() in any practical cycle budget. Requires
    /// --no-bootrom.
    #[arg(long)]
    skip_data: bool,

    /// Path to the RP2350 bootrom binary (32 kB). If omitted, uses the
    /// pinned silicon bootrom bundled with the rp2350-emu crate (which
    /// requires the crate's roms/ dir to be present). Get the bootrom from
    /// https://github.com/0x4D44/picoem (roms/rp2350/bootrom-combined.bin).
    #[arg(long)]
    bootrom: Option<PathBuf>,
}

fn parse_addr(s: &str) -> Result<u32, String> {
    if let Some(stripped) = s.strip_prefix("0x") {
        u32::from_str_radix(stripped, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u32>().map_err(|e| e.to_string())
    }
}

fn load_firmware(emu: &mut Emulator, path: &PathBuf) -> Result<(), String> {
    use elf::abi::PT_LOAD;
    use elf::endian::AnyEndian;
    use elf::ElfStream;

    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    // `ElfStream` needs a Read+Seek, so wrap the bytes in a Cursor.
    let cursor = std::io::Cursor::new(&data[..]);
    let elf = ElfStream::<AnyEndian, _>::open_stream(cursor)
        .map_err(|e| format!("parse ELF: {e}"))?;

    // Collect the flash-resident PT_LOAD segments (p_paddr in 0x10000000..).
    // The firmware links its sections with gaps (vector table, start_block,
    // .text are not contiguous), but the emulator's `load_flash` takes one
    // contiguous blob. Build a contiguous buffer spanning the whole flash
    // range and fill gaps with 0xFF (erased NOR).
    #[derive(Debug)]
    struct Seg {
        addr: u32,
        data: Vec<u8>,
    }
    let mut segs: Vec<Seg> = Vec::new();
    let mut loaded = 0usize;
    for phdr in elf.segments() {
        if phdr.p_type != PT_LOAD || phdr.p_filesz == 0 {
            continue;
        }
        let addr = phdr.p_paddr;
        if addr > u32::MAX as u64 || !(FLASH_BASE as u64..0x1400_0000u64).contains(&addr) {
            continue;
        }
        let addr32 = addr as u32;
        let start = phdr.p_offset as usize;
        let len = phdr.p_filesz as usize;
        let seg_data = data[start..start + len].to_vec();
        if seg_data.is_empty() {
            continue;
        }
        loaded += seg_data.len();
        segs.push(Seg {
            addr: addr32,
            data: seg_data,
        });
        println!(
            "  seg @{addr32:#010x}..{:#010x} ({} bytes)",
            addr32 + len as u32,
            len
        );
    }

    if segs.is_empty() {
        return Err("no loadable flash segments found in ELF".to_string());
    }

    // Build contiguous flash buffer from FLASH_BASE to end of last segment.
    let flash_end = segs.iter().map(|s| s.addr + s.data.len() as u32).max().unwrap();
    let flash_size = (flash_end - FLASH_BASE) as usize;
    let mut flash = vec![0xFFu8; flash_size]; // 0xFF = erased NOR
    for seg in &segs {
        let off = (seg.addr - FLASH_BASE) as usize;
        flash[off..off + seg.data.len()].copy_from_slice(&seg.data);
    }

    println!(
        "  flash image: {flash_size} bytes (0x{FLASH_BASE:08x}..0x{:08x})",
        FLASH_BASE + flash_size as u32
    );
    emu.load_flash(&flash);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("fapico2-emu-harness");
    println!("  firmware: {}", args.firmware.display());

    // Build the emulator: single Arm core (core 0), default config.
    // step_quantum=1 lets us trace instruction-by-instruction (each step()
    // advances exactly one cycle group / instruction).
    let config = Config::default();
    let mut emu = EmulatorBuilder::new(config)
        .arch(Arch::Arm)
        .step_quantum(1)
        .build()
        .expect("emulator build failed");

    // Load the firmware binary into flash.
    println!("loading firmware:");
    load_firmware(&mut emu, &args.firmware).expect("load_firmware");

    // Read the firmware vector table (flash words 0, 1).
    let initial_sp = emu.peek(FLASH_BASE);
    let reset_vec = emu.peek(FLASH_BASE + 4);
    println!("  vector table: SP={initial_sp:#010x}  reset={reset_vec:#010x}");

    if args.no_bootrom {
        // Skip the bootrom: park PC at the reset vector and SP at the
        // vector-table value. This isolates the firmware boot path
        // (Reset handler → main) from the bootrom's IMAGE_DEF scan.
        //
        // Without this, exceptions would vector into the (unloaded) bootrom
        // region at 0x00000000. Point VTOR at the firmware's vector table
        // and mask IRQs so the firmware runs undisturbed.
        println!("  --no-bootrom: setting PC={reset_vec:#010x} SP={initial_sp:#010x}");
        emu.mmio_write32(0xE000_ED08, FLASH_BASE); // VTOR = firmware VT
        let core = emu.core_mut(0);
        core.regs.set_pc(reset_vec | 1); // thumb bit
        core.regs.set_sp(initial_sp);
        core.regs.msp = initial_sp;
        core.regs.msplim = 0; // firmware's Reset handler sets this immediately
        core.regs.primask = 1; // disable IRQs for the boot trace
    } else if let Some(path) = &args.bootrom {
        // Load the RP2350 bootrom from an explicit path so the emulator boots
        // like real hardware (bootrom scans the IMAGE_DEF start_block, then
        // jumps to the firmware reset vector).
        let bootrom = std::fs::read(path)
            .map_err(|e| format!("read bootrom {}: {e}", path.display()))?;
        println!("  bootrom loaded: {} bytes from {}", bootrom.len(), path.display());
        emu.load_bootrom(&bootrom);
    } else {
        // Fall back to the pinned silicon bootrom bundled with rp2350-emu.
        let bootrom = rp2350_emu::load_pinned_silicon_bootrom()
            .map_err(|e| format!("load bootrom: {e}"))?;
        println!("  bootrom loaded (pinned): {} bytes", bootrom.len());
        emu.load_bootrom(&bootrom);
    }

    // Dump the bootrom vector table (words 0..16) so we can see what the
    // core will fetch on reset.
    println!("  bootrom VT (first 16 words):");
    for i in 0..16u32 {
        print!(" {:#010x}", emu.peek(i * 4));
    }
    println!();

    let core = emu.core(0);
    println!(
        "  start: PC={:#010x} SP={:#010x} MSPLIM={:#010x}",
        core.regs.pc(),
        core.regs.sp(),
        core.regs.msplim
    );

    // Run until fault, stop target, or cycle budget exhausted.
    let mut cycles: u64 = 0;
    let mut last_pc: u32 = core.regs.pc();
    let mut last_log_pc: u32 = core.regs.pc();
    let mut watchdog_same_pc: u64 = 0;
    let mut data_copied = false;
    let watchdog_threshold: u64 = 10_000; // stuck if PC unchanged this many steps
    let log_interval: u64 = 100_000; // log PC this often even if unchanged
    let mut next_heartbeat: u64 = log_interval * 10;

    println!("\n--- execution begin (max {} cycles) ---", args.max_cycles);

    while cycles < args.max_cycles {
        let pc_before = emu.core(0).regs.pc();

        match emu.step() {
            Ok(stepped) => {
                cycles += stepped;
            }
            Err(e) => {
                let c = emu.core(0);
                println!(
                    "\n[FAULT] after {cycles} cycles: {e:?}\n  PC={:#010x} SP={:#010x} MSPLIM={:#010x} LR={:#010x}",
                    c.regs.pc(),
                    c.regs.sp(),
                    c.regs.msplim,
                    c.regs.lr()
                );
                print_fault_symptoms(&emu);
                std::process::exit(0);
            }
        }

        let c = emu.core(0);
        let pc = c.regs.pc();
        let sp = c.regs.sp();
        let msplim = c.regs.msplim;
        let lr = c.regs.lr();
        let ipsr = c.regs.ipsr();
        // Decide whether to skip __pre_init while we still have the
        // immutable borrow; the actual mutation happens after `c` drops.
        let skip_pre_init = args.skip_pre_init;
        let hit_hardfault = pc == 0x10001f46;
        let hit_other_fault = pc == 0x10001f42 || pc == 0x10001f3e || pc == 0x10001f36;
        // Drop the immutable borrow before any mutable access below.
        drop(c);

        // Trace every instruction if requested.
        if args.trace {
            println!("  {cycles:>8} PC={pc:#010x} SP={sp:#010x} MSPLIM={msplim:#010x}");
        }

        // Detect a stuck PC (branch-to-self / tight loop = classic dark-boot).
        if pc == pc_before {
            watchdog_same_pc += 1;
            if watchdog_same_pc == watchdog_threshold {
                println!(
                    "\n[STUCK] PC unchanged for {watchdog_threshold} steps at {pc:#010x} after {cycles} cycles"
                );
                println!("  PC={pc:#010x} SP={sp:#010x} MSPLIM={msplim:#010x} LR={lr:#010x}");
                print_fault_symptoms(&emu);
                std::process::exit(0);
            }
        } else {
            watchdog_same_pc = 0;
        }

        // Detect entry into a fault handler (PC at a known fault vector).
        // The Cortex-M33 fault handlers are weak symbols bracketing this
        // address range; catch the core spinning in one.
        if hit_hardfault {
            println!("\n[HardFault] entered HardFault_ at {cycles} cycles");
            println!("  PC={pc:#010x} SP={sp:#010x} MSPLIM={msplim:#010x} LR={lr:#010x}");
            print_fault_symptoms(&emu);
            std::process::exit(0);
        }

        // Catch other fault handlers (NMI, BusFault, UsageFault, etc.).
        if hit_other_fault {
            println!(
                "\n[FAULT_HANDLER] entered fault loop at {pc:#010x} after {cycles} cycles, IPSR={ipsr}"
            );
            print_fault_symptoms(&emu);
            std::process::exit(0);
        }

        // Detect "fell off the end": with --no-bootrom the bootrom region is
        // zero-filled (VTOR points at the firmware VT, so a hard fault that
        // doesn't route to a real handler vectorizes into 0x0). If PC drops
        // below the flash base after having executed in flash, that is the
        // fault signature — dump the fault registers and stop.
        if args.no_bootrom && pc < 0x10000000 && last_pc >= 0x10000000 {
            println!(
                "\n[FALL] PC left flash -> {pc:#010x} after {cycles} cycles (vectorized into the zero region)"
            );
            println!("  PC={pc:#010x} SP={sp:#010x} MSPLIM={msplim:#010x} LR={lr:#010x}");
            print_fault_symptoms(&emu);
            std::process::exit(0);
        }

        // __pre_init (0x10001000) touches the PLL_USB peripheral at
        // 0x40018004, which the emulator doesn't implement — it faults
        // there. On real hardware this works. To debug the firmware's own
        // boot path past this point, detect the `bl __pre_init`
        // instruction (PC=0x10000206; trace shows 0x10000207 with the
        // thumb bit set) and fast-forward PC past it to 0x1000020a,
        // simulating __pre_init as a no-op.
        if skip_pre_init && (pc & !1) == 0x10000206 {
            println!("  [skip __pre_init] PC {pc:#010x} -> 0x1000020a");
            emu.core_mut(0).regs.set_pc(0x1000020a);
        }

        // Skip .bss clearing: in the Reset handler's zero-init loop, r0 is
        // the write pointer and r1 the end. Setting r0=r1 forces the loop's
        // `cmp r0, r1; beq exit` to branch to exit on the next iteration.
        if args.skip_bss && (pc & !1) >= 0x10000210 && (pc & !1) <= 0x10000216 {
            let r1 = emu.core(0).reg(1);
            emu.core_mut(0).set_reg(0, r1);
        }

        // Skip the .data copy: in the Reset handler's copy loop, r0 is the
        // RAM write pointer, r1 the RAM end, r2 the flash source. On the
        // first hit, bulk-copy the whole init image via debug peek/poke
        // (faithful to what the loop would do), then set r0=r1 to exit.
        if args.skip_data
            && !data_copied
            && (pc & !1) >= 0x1000021e
            && (pc & !1) <= 0x10000226
        {
            let (r0, r1, r2) = {
                let c = emu.core(0);
                (c.reg(0), c.reg(1), c.reg(2))
            };
            let mut dst = r0;
            let mut src = r2;
            while dst < r1 {
                emu.poke(dst, emu.peek(src));
                dst += 4;
                src += 4;
            }
            emu.core_mut(0).set_reg(0, r1);
            data_copied = true;
            println!(
                "  [skip .data copy] bulk-copied {:#010x}..{r1:#010x} from {r2:#010x} ({} bytes)",
                r0,
                r1 - r0
            );
        }

        // Emulate ARMv8-M atomic instructions that the emulator doesn't
        // implement. The firmware uses these throughout (embassy-rp
        // RpSpinlockCs critical section, embassy-executor waker atomics,
        // core::sync::atomic). For single-core operation, load-acquire is
        // equivalent to a normal load, and store-exclusive (stlex/stlexb)
        // always succeeds. We decode the 32-bit Thumb-2 atomic opcode at
        // PC, perform the equivalent non-atomic operation, and advance PC
        // past the 4-byte instruction.
        //
        // Atomic loads:  111010001101 rn rt 1111 size 1111 = 0xE8D..F..
        //   size[7:4]: 8=ldab 9=ldah A=lda C=ldaexb D=ldaexh E=ldaex
        // Atomic stores: 111010001100 rn rt 1111 size rd  = 0xE8C..?..
        //   size[7:4]: 8=stlb 9=stlh A=stl C=stlexb D=stlexh E=stlex
        {
            // Read the atomic instruction and ALL operand values while we
            // only hold an immutable borrow, then drop that borrow before
                // mutating. This satisfies the borrow checker.
            let (do_load, do_store, rn, rt, rd, size) = {
                let instr = emu.peek(pc & !1);
                let hw1 = instr & 0xFFFF;
                let hw2 = instr >> 16;
                // Atomic load: 0xE8D0 top, byte[3]=0xF, byte[0]=0xF
                if hw2 == 0xE8D0 && (hw1 & 0xFF00) == 0xF000 && (hw1 & 0x000F) == 0xF {
                    let rn = (instr & 0x000F) as usize;
                    let rt = ((instr >> 12) & 0xF) as usize;
                    let size = (instr >> 4) & 0xF;
                    (true, false, rn, rt, 0, size)
                }
                // Atomic store: 0xE8C0 top, byte[3]=0xF
                else if hw2 == 0xE8C0 && (hw1 & 0xFF00) == 0xF000 {
                    let rn = (instr & 0x000F) as usize;
                    let rt = ((instr >> 12) & 0xF) as usize;
                    let rd = (hw1 & 0xF) as usize;
                    let size = (instr >> 4) & 0xF;
                    (false, true, rn, rt, rd, size)
                } else {
                    (false, false, 0, 0, 0, 0)
                }
            };

            if do_load {
                let c = emu.core(0);
                let addr = c.reg(rn);
                let val = match size {
                    0x8 | 0xC => {
                        // byte load (ldab / ldaexb)
                        let word = emu.peek(addr & !3);
                        (word >> ((addr & 3) * 8)) & 0xFF
                    }
                    0x9 | 0xD => {
                        // halfword load (ldah / ldaexh)
                        let word = emu.peek(addr & !3);
                        (word >> ((addr & 2) * 8)) & 0xFFFF
                    }
                    _ => {
                        // word load (lda / ldaex)
                        emu.peek(addr)
                    }
                };
                let c = emu.core_mut(0);
                c.set_reg(rt, val);
                c.regs.set_pc((pc & !1) + 4);
            } else if do_store {
                let c = emu.core(0);
                let addr = c.reg(rn);
                let val = c.reg(rt);
                match size {
                    0x8 | 0xC => {
                        // byte store (stlb / stlexb)
                        let aligned = addr & !3;
                        let shift = (addr & 3) * 8;
                        let mask = !(0xFFu32 << shift);
                        let old = emu.peek(aligned);
                        emu.poke(aligned, (old & mask) | ((val & 0xFF) << shift));
                    }
                    0x9 | 0xD => {
                        // halfword store (stlh / stlexh)
                        let aligned = addr & !3;
                        let shift = (addr & 2) * 8;
                        let mask = !(0xFFFFu32 << shift);
                        let old = emu.peek(aligned);
                        emu.poke(aligned, (old & mask) | ((val & 0xFFFF) << shift));
                    }
                    _ => {
                        // word store (stl / stlex)
                        emu.poke(addr, val);
                    }
                }
                let c = emu.core_mut(0);
                c.set_reg(rd, 0); // store-exclusive success
                c.regs.set_pc((pc & !1) + 4);
            }
        }

        // Log when PC changes to a new address (coarse execution trace).
        // This shows the flow without per-instruction verbosity.
        if pc != last_pc && !args.trace {
            println!("  {cycles:>8} PC={pc:#010x} SP={sp:#010x} MSPLIM={msplim:#010x}");
            last_pc = pc;
        }
        // Periodic heartbeat even when stuck — includes r0 to track .bss
        // clearing progress (r0 should advance each pass).
        if cycles >= next_heartbeat && !args.trace {
            let r0 = emu.core(0).reg(0);
            let r1 = emu.core(0).reg(1);
            println!(
                "  {cycles:>8} [heartbeat] PC={pc:#010x} r0={r0:#010x} r1={r1:#010x}"
            );
            next_heartbeat += log_interval * 10;
        }

        if let Some(target) = args.stop_at {
            if pc == target {
                println!("\n[STOP] reached target {target:#010x} after {cycles} cycles");
                println!("  PC={pc:#010x} SP={sp:#010x} MSPLIM={msplim:#010x} LR={lr:#010x}");
                break;
            }
        }
    }

    let c = emu.core(0);
    println!(
        "\n[END] cycle budget ({}) exhausted\n  PC={:#010x} SP={:#010x} MSPLIM={:#010x}",
        args.max_cycles,
        c.regs.pc(),
        c.regs.sp(),
        c.regs.msplim
    );
    Ok(())
}

/// Heuristic post-mortem: read fault registers and bus state to classify the
/// crash. Best-effort — the emulator's fault model is still maturing.
fn print_fault_symptoms(emu: &Emulator) {
    // CFSR is at 0xE000_ED28, HFSR at 0xE000_ED2C, MMFAR at 0xE000_ED34,
    // BFAR at 0xE000_ED38. These are in the PPB; peek bypasses bus timing.
    let cfsr = emu.peek(0xE000_ED28);
    let hfsr = emu.peek(0xE000_ED2C);
    let mmfar = emu.peek(0xE000_ED34);
    let bfar = emu.peek(0xE000_ED38);
    let c = emu.core(0);
    println!("  fault regs: CFSR={cfsr:#010x} HFSR={hfsr:#010x} MMFAR={mmfar:#010x} BFAR={bfar:#010x}");
    println!(
        "  xPSR={:#010x} IPSR={} CONTROL={:#010x} (handler mode: {})",
        c.regs.xpsr,
        c.regs.ipsr(),
        c.regs.control,
        c.regs.in_handler_mode()
    );
    // If MSP is below MSPLIM, that's a stack-of (STKOF) — the previous
    // session's theory.
    if c.regs.msp < c.regs.msplim {
        println!(
            "  !! STKOF: MSP ({:#010x}) < MSPLIM ({:#010x})",
            c.regs.msp, c.regs.msplim
        );
    }
}
