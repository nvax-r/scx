//! Per-CPU PMU plumbing for `scx_invariant` (Task 5 of PLAN.md).
//!
//! Userspace opens four hardware counters per CPU as system-wide,
//! CPU-pinned events (`pid = -1`, `cpu = N`, `disabled = 0`) and pushes
//! the resulting fds into four `BPF_MAP_TYPE_PERF_EVENT_ARRAY` maps
//! indexed by `cpu_id`. The BPF side reads them via
//! `bpf_perf_event_read_value(map, cpu, ...)` on every running/stopping
//! callback and emits per-quantum deltas into `evt_running` /
//! `evt_stopping`.
//!
//! Failure policy (per `work/task.md`):
//! - A single CPU failing to open a counter is logged once and that
//!   CPU's slot stays unset; the BPF side reads zero for that slot,
//!   which the reader interprets as "no PMU data".
//! - A counter type that fails on every CPU is logged at info level and
//!   the entire counter type is skipped.
//! - The recorder never refuses to start because of PMU failures —
//!   running on a host with `kernel.perf_event_paranoid >= 2` and no
//!   `CAP_PERFMON` is more useful than not running at all.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use libbpf_rs::MapCore;
use log::{info, warn};
use scx_utils::perf;

use crate::BpfSkel;

/// ARMv8 PMUv3 architectural event codes (matches
/// `include/linux/perf/arm_pmuv3.h` in the upstream kernel).
///
/// `PERF_TYPE_HARDWARE` does not provide portable encodings for L2 cache
/// refills or backend stalls, so we emit them as `PERF_TYPE_RAW` events.
/// This is aarch64-specific by design — the host this project targets
/// (Neoverse V2, kernel 6.17 per PLAN.md §12) exposes these via the
/// `armv8_pmuv3_0` PMU. x86 support is intentionally out of scope.
const ARMV8_PMUV3_PERFCTR_L2D_CACHE_REFILL: u64 = 0x0017;
const ARMV8_PMUV3_PERFCTR_STALL_BACKEND: u64 = 0x0024;

/// One logical counter spec. `name` only feeds logs; the kernel cares
/// about `(type_, config)`.
struct CounterSpec {
    name: &'static str,
    type_: u32,
    config: u64,
}

/// The four counters this recorder fills in. Order is for log
/// readability only — each counter has its own dedicated map on the
/// BPF side, so there's no implicit positional contract here.
const COUNTERS: [CounterSpec; 4] = [
    CounterSpec {
        name: "instructions",
        type_: perf::bindings::PERF_TYPE_HARDWARE,
        config: perf::bindings::PERF_COUNT_HW_INSTRUCTIONS as u64,
    },
    CounterSpec {
        name: "cycles",
        type_: perf::bindings::PERF_TYPE_HARDWARE,
        config: perf::bindings::PERF_COUNT_HW_CPU_CYCLES as u64,
    },
    CounterSpec {
        name: "l2_misses",
        type_: perf::bindings::PERF_TYPE_RAW,
        config: ARMV8_PMUV3_PERFCTR_L2D_CACHE_REFILL,
    },
    CounterSpec {
        name: "stall_backend",
        type_: perf::bindings::PERF_TYPE_RAW,
        config: ARMV8_PMUV3_PERFCTR_STALL_BACKEND,
    },
];

/// Owned perf-event fds. Outer dimension matches `COUNTERS` (length 4),
/// inner dimension is per CPU. `OwnedFd` closes the fd on drop, which
/// is what we want — once the recorder exits, the perf events go away.
pub struct Pmu {
    fds: Vec<Vec<Option<OwnedFd>>>,
}

impl Pmu {
    /// Open all four counters for every CPU in `[0, nr_cpus)`.
    ///
    /// Infallible by design (per `work/task.md` "Approach D rejected"):
    /// the recorder must always start, even when no PMU access is
    /// available. Per-CPU failures are logged once at warn level and
    /// leave that slot as `None`. A counter that fails on every CPU is
    /// logged once at info level and the whole counter type is left
    /// unmapped — BPF reads return zero for unset slots and the trace
    /// records zero, matching the pre-Task-5 placeholder semantics.
    pub fn open(nr_cpus: u16) -> Self {
        let mut fds: Vec<Vec<Option<OwnedFd>>> = Vec::with_capacity(COUNTERS.len());

        for spec in COUNTERS.iter() {
            let mut per_cpu: Vec<Option<OwnedFd>> = Vec::with_capacity(nr_cpus as usize);
            let mut opened = 0u32;
            let mut first_err: Option<std::io::Error> = None;

            for cpu in 0..nr_cpus as i32 {
                match open_one(spec, cpu) {
                    Ok(fd) => {
                        per_cpu.push(Some(fd));
                        opened += 1;
                    }
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                        per_cpu.push(None);
                    }
                }
            }

            if opened == 0 {
                // Whole-counter failure (most common: no `CAP_PERFMON`,
                // perf_event_paranoid too high, or a VM PMU that just
                // doesn't expose this raw event). One info log, no warn
                // spam — the field will just be zero in the trace.
                let err = first_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                info!(
                    "PMU counter '{}' unavailable on this host ({}); \
                     trace will record 0 for this field",
                    spec.name, err
                );
            } else if opened < nr_cpus as u32 {
                warn!(
                    "PMU counter '{}' opened on {}/{} CPUs; \
                     unmapped CPUs will record 0",
                    spec.name, opened, nr_cpus
                );
            }

            fds.push(per_cpu);
        }

        Self { fds }
    }

    /// Push opened fds into the BPF perf-event-array maps. Must run
    /// **after** `scx_ops_load!` (the maps must exist in the kernel)
    /// and **before** `scx_ops_attach!` (the callbacks read these maps
    /// from their first invocation).
    ///
    /// Infallible by design (same rationale as `Pmu::open`).
    /// `bpf_map_update_elem` failure modes here are:
    ///   * `ENOMEM` — transient kernel pressure; demote to a warn so
    ///     the recorder keeps producing useful events with zero PMU
    ///     fields, rather than failing the whole capture.
    ///   * `EINVAL` — programming error (wrong map type / size);
    ///     would be caught in dev. A loud warn is enough at runtime.
    ///   * `E2BIG` — `cpu >= max_entries (1024)`. Cannot happen on
    ///     the target host (144 CPUs); demoting still matches policy.
    ///
    /// In all cases the slot stays unset and the BPF reads return 0
    /// for that (counter, cpu) pair. We log per-counter rather than
    /// per-(counter, cpu) to avoid spam when a systemic failure hits
    /// every CPU.
    pub fn install(&self, skel: &BpfSkel) {
        // Tied to the order of `COUNTERS`; if that order changes, this
        // table must move with it. Kept as a local rather than a field
        // on `CounterSpec` so the bpf_skel map handles aren't pulled
        // into a `'static`-typed table.
        let maps: [&libbpf_rs::Map; 4] = [
            &skel.maps.pmu_instructions,
            &skel.maps.pmu_cycles,
            &skel.maps.pmu_l2_misses,
            &skel.maps.pmu_stall_backend,
        ];

        for (idx, spec) in COUNTERS.iter().enumerate() {
            let map = maps[idx];
            let mut installed = 0u32;
            let mut failed = 0u32;
            let mut first_err: Option<libbpf_rs::Error> = None;

            for (cpu, slot) in self.fds[idx].iter().enumerate() {
                let Some(fd) = slot else { continue };
                let key = (cpu as u32).to_ne_bytes();
                let val = (fd_as_i32(fd) as u32).to_ne_bytes();
                match map.update(&key, &val, libbpf_rs::MapFlags::ANY) {
                    Ok(()) => installed += 1,
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                        failed += 1;
                    }
                }
            }

            if failed > 0 {
                let err = first_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                warn!(
                    "PMU counter '{}' map install: {} ok, {} failed ({}); \
                     failed CPUs will record 0",
                    spec.name, installed, failed, err
                );
            }
        }
    }
}

/// `OwnedFd::as_raw_fd` requires `AsRawFd`; importing the trait inline
/// is noisy and only used here, so wrap it once.
fn fd_as_i32(fd: &OwnedFd) -> i32 {
    use std::os::fd::AsRawFd;
    fd.as_raw_fd()
}

fn open_one(spec: &CounterSpec, cpu: i32) -> std::io::Result<OwnedFd> {
    let mut attr = perf::bindings::perf_event_attr {
        type_: spec.type_,
        size: std::mem::size_of::<perf::bindings::perf_event_attr>() as u32,
        config: spec.config,
        ..Default::default()
    };
    // `disabled = 0`: counter starts running immediately. We never
    // call PERF_EVENT_IOC_ENABLE, so this matters.
    attr.set_disabled(0);
    // `inherit = 0`: this is a system-wide CPU-pinned event, not a
    // per-task event. Inheritance would be a config error rather than
    // an attribute we want; set explicitly for clarity.
    attr.set_inherit(0);
    // `exclude_hv = 1`: ignore hypervisor cycles when the host is a
    // guest. The Neoverse V2 host this targets is bare-metal so this
    // is a no-op there, but it's the right hygiene for any kvm/vm.
    attr.set_exclude_hv(1);

    // pid=-1, cpu=N → measure all tasks on a single CPU. group_fd=-1
    // (no group leader). flags=0.
    let raw: RawFd = unsafe { perf::perf_event_open(&mut attr, -1, cpu, -1, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: perf_event_open returned a valid fd and we hand ownership
    // to OwnedFd, which closes it on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Convenience wrapper used by `main.rs` to keep PMU plumbing out of
/// the `Scheduler::init` body. Infallible — see `Pmu::open` and
/// `Pmu::install` for the rationale.
pub fn open_and_install(skel: &BpfSkel, nr_cpus: u16) -> Pmu {
    let pmu = Pmu::open(nr_cpus);
    pmu.install(skel);
    pmu
}
