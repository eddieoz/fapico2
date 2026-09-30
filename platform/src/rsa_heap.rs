//! S-724: static heap backing the software-RSA trussed backend on the device.
//!
//! [`trussed_rsa_alloc::SoftwareRsa`] executes RSA over `alloc` (the `rsa`
//! crate's big-integer math). The device build is otherwise heap-free, so
//! the arm binaries linking the `rsa-backend` feature carry a dedicated
//! static heap, initialized exactly once by [`DeviceBackend::boot`]
//! (`device::DeviceBackend::boot`) before any OpenPGP request runs. Arm
//! binaries that never call `boot` simply keep the allocator empty — RSA
//! requests answer `OutOfMemory`-style errors instead of wedging (the
//! US-413 wedge class is a blocking loop, not an allocator miss).
//!
//! Size (US-956: 128 KiB → 48 KiB, **re-derived from measurement**): the
//! peak-instrumented host mirror (`apps/openpgp/tests/rsa_heap_peak.rs`)
//! measures the high-water mark of `live − baseline` across the exact span in
//! which `SoftwareRsa.request` allocates (the full card flow, with the
//! measurement window wrapped around the one APDU that drives the software
//! RSA backend). The table below covers **every RSA workload the card can
//! reach today**, at every modulus width it serves:
//!
//! | operation | RSA-2048 | RSA-3072 | RSA-4096 |
//! |---|---:|---:|---:|
//! | GENERATE ASYMMETRIC KEY PAIR | 7,018 | 13,034 | 13,162 |
//! | PSO:SIGN | — | — | **24,792** |
//! | PSO:DECIPHER | 12,520 | 24,040 | 24,168 |
//! | PUT KEY (INS DB) private import | 5,083 | 7,961 | 9,961 |
//! | ambient control (GET DATA, non-keygen) | 256 | 256 | 256 |
//!
//! Rows marked as a 4096-only measurement are the two the card's own
//! generation-advertisement pins at that width; the blank cells are shapes
//! the card never reaches at that width (RSA sign/decipher is only exercised
//! at 4096 because that is the size the US-942 end-to-end scenario drives).
//! **Sizing worst case = 24,792 B** (PSO:SIGN, RSA-4096). Re-measured
//! 2026-09-26 at this tip, max of 3 runs each, through that same test binary,
//! with the enforceable cap armed on every run (US-957 added the decipher and
//! import rows; US-956 measured the rest).
//!
//! The peaks are **byte-identical across repeats at every size** — they are a
//! structural function of the modulus width (the fixed-width big-integer
//! working set of `RsaPrivateKey::new` / PKCS#8 load / CRT modexp / blinded
//! unpadding / `from_components` + `precompute`), not a data-dependent
//! prime-search draw. That is what makes a tight-but-measured bound defensible
//! here rather than a guess.
//!
//! **Why 48 KiB and not 13,162 B.** The keygen-only peak is *not* the worst
//! case: PSO:SIGN on a 4096-bit key peaks at 24,792 B, ~1.9x the largest
//! keygen, because the sign path additionally deserializes the PKCS#8 key
//! into `BigUint`s and runs a blinded CRT modexp. PSO:DECIPHER at 4096 comes
//! within 624 B of it (24,168 B — same shape, unpadding instead of
//! re-encoding), and PUT KEY import is the cheapest of all (9,961 B) because
//! it only builds `p·q` and precomputes the CRT inverse. 49,152 B is
//! **1.98x** the worst measured peak and **3.73x** the largest keygen peak.
//! The multiplier is deliberate: see "Failure-on-overflow semantics" below —
//! there is no recoverable OOM, so the headroom has to absorb one extra `Vec`
//! doubling rung in the sign path before it costs a device.
//!
//! The upstream `trussed-rsa-alloc` warning that RSA-4096 generation may
//! exceed 128 KiB remains **measured-false** for this stack.
//!
//! Failure-on-overflow semantics: the `rsa`/`num-bigint-dig` stack grows its
//! buffers with *infallible* `Vec` allocations, so an exhausted heap does not
//! surface as a catchable error — `handle_alloc_error` aborts the process
//! (`panic = "abort"` on device). That is why the bound is 1.98x a measured
//! worst case and not 1.0x, and why the capacity regression stays pinned by
//! the rsa_heap_peak tests, which re-run **keygen, PSO:SIGN, PSO:DECIPHER
//! and PUT KEY import** with the enforceable [`RSA_HEAP_SIZE`] limit armed (an
//! overrun is a loud abort, never a silent one).
//!
//! Do NOT grow the heap without re-deriving it the same way: the RP2350 has
//! 532,480 B of SRAM and the boot-path statics already claim most of it (see
//! `docs/size-report.md`); a 2x raise here does not fit.

use linked_list_allocator::LockedHeap;

/// Device RSA heap capacity. Mirrored by `DEVICE_RSA_HEAP_SIZE` in
/// `apps/openpgp/tests/rsa_heap_peak.rs`, which arms the same limit on the
/// host mirror so the two can never drift silently.
pub const RSA_HEAP_SIZE: usize = 48 * 1024;
static mut RSA_HEAP: [u8; RSA_HEAP_SIZE] = [0; RSA_HEAP_SIZE];

#[global_allocator]
static RSA_ALLOC: LockedHeap = LockedHeap::empty();

/// Initialize the software-RSA heap exactly once. Must run before the first
/// `alloc` (call it from the single boot path, before the client serves
/// requests).
///
/// # Safety
///
/// The heap region must not be aliased by any other memory user; init must
/// happen before the first allocation.
pub unsafe fn init() {
    let start = core::ptr::addr_of_mut!(RSA_HEAP).cast::<u8>();
    RSA_ALLOC.lock().init(start, RSA_HEAP_SIZE);
}
