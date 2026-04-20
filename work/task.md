# Task: PMU integration for scx_invariant (Task 5)

> **Premise:** Task 3 (cgroup filtering, both halves) is frozen as Done in
> `scheds/rust/scx_invariant/PLAN.md` §9. `src/cgroup.rs` is in tree and the
> `record` subcommand works in both spawn and system-wide modes. PMU is the
> next pending item; Tick recording (Task 7) follows it.

## Status going in

The trace format already reserves PMU fields:

- `evt_running` carries `cpu_perf: u16` and four `pmc_*` u64s (instructions,
  cycles, L2 misses, backend stalls) — see `src/bpf/intf.h:36-49`.
- `evt_stopping` carries the same four `pmc_*` u64s — see
  `src/bpf/intf.h:51-62`.
- `task_ctx` in BPF already declares matching `pmc_*_start` slots
  (`src/bpf/main.bpf.c:45-60`) so per-task snapshot storage is in place.

The BPF callbacks set every PMU output to literal `0` today
(`main.bpf.c:199`, `203-206`, `245-248`). This task replaces those
placeholders with real counter reads and turns `cpu_perf` into a real
frequency-state sample. Nothing else about the recording pipeline changes.

## Goal

Populate the PMU fields with **per-quantum hardware counter deltas**
(end-of-running minus start-of-running) for the four counters declared in
the trace format, plus the kernel's current frequency-state hint via
`scx_bpf_cpuperf_cur()`. Per-quantum semantics matter: the reader analyzes
IPC, miss rate, and stall ratios over individual on-CPU intervals, not
lifetime totals.

This unlocks the IPC / cache / stall / migration-cost analysis that PLAN.md
§10 promises ("per-quantum PMU profile — IPC, L2 miss rate, backend stall
breakdown") without changing the on-disk format or the reader.

## Approach

**A — userspace `perf_event_open` per CPU + BPF perf-event-array map**
(chosen):

- Userspace opens four PMU events per CPU as system-wide, CPU-pinned
  counters (`pid = -1`, `cpu = N`, `disabled = 0`). On a single CPU, the
  difference between consecutive reads during a single quantum equals the
  work that the on-CPU task did, because nothing else can run there in
  the meantime. Counts include kernel-mode work (interrupts, softirqs);
  this is the standard accuracy/cost tradeoff and is acceptable for our
  analysis.
- The four resulting fds per CPU are inserted into a
  `BPF_MAP_TYPE_PERF_EVENT_ARRAY` indexed by `cpu_id`. One map per
  counter type, not one map per CPU — matches the conventional libbpf
  pattern and keeps BPF lookups clean.
- BPF reads via `bpf_perf_event_read_value()` (not the older
  `bpf_perf_event_read()`): the value variant returns `enabled` and
  `running` time alongside the count, so we can detect (and, if needed,
  scale) multiplexed reads. With four events per CPU we should fit on
  every PMU we care about without multiplexing, but the helper costs the
  same and the safety is free.
- `running` callback snapshots the four start values into `task_ctx`
  (slots already exist).
- `stopping` callback re-reads each counter, computes
  `delta = end - start`, writes into the event. Wraparound is u64; not a
  practical concern for any quantum we care about.
- `running` also calls `scx_bpf_cpuperf_cur(cpu)` and stores the result
  in `evt->cpu_perf`.

Cgroup gating from Task 3 already short-circuits all of this for
out-of-scope tasks — no additional filter needed.

Rejected alternatives:

- **B. Process-attached `perf_event_open(pid = task_pid)`.** Requires
  opening events per task, scaling poorly with task count (we'd have to
  hook fork/exit). Doesn't compose with our cgroup-membership filter.
  Out.
- **C. PMU read in `tick` only.** Would skip the per-quantum delta
  entirely and only sample at HZ boundaries. Loses the precise on-CPU
  interval that the trace format is designed for. EVT_TICK is its own
  task (Task 7) and is additive, not a substitute.
- **D. Refuse to start without PMU access.** A recorder that runs
  without PMU is more useful than one that doesn't run at all
  (e.g. inside a VM, or with `kernel.perf_event_paranoid >= 2` and no
  `CAP_PERFMON`). We log and continue with PMU disabled instead.

## PMU event selection

Four counters, mapped to whatever the host PMU calls them:

| Logical field | Generic perf event | Notes |
|---|---|---|
| `pmc_instructions` | `PERF_COUNT_HW_INSTRUCTIONS` | Universal. |
| `pmc_cycles` | `PERF_COUNT_HW_CPU_CYCLES` | Universal. |
| `pmc_l2_misses` | `PERF_COUNT_HW_CACHE_L1D` `READ` `MISS` *or* an arch-specific raw event | See note below. |
| `pmc_stall_backend` | Raw event; arch-specific encoding | See note below. |

Generic `perf_event_attr.type = PERF_TYPE_HARDWARE` covers instructions
and cycles on every supported arch. The "L2 misses" and "backend stall"
fields require platform-specific encodings — there is no portable generic
event for either. Initial implementation targets the host this project is
developed on (aarch64 Neoverse V2 per PLAN.md §12); use the ARMv8 PMUv3
event codes (`L2D_CACHE_REFILL`, `STALL_BACKEND` from the ARMv8 PMU
common architectural events). x86 support is not in scope.

If event open fails for a counter on a given CPU, leave that counter's
fd empty in the map; BPF reads will return an error and we'll write `0`
for that field. Don't refuse to start.

## Userspace mechanics

New file: `scheds/rust/scx_invariant/src/pmu.rs` (~150 LOC).

- `pub struct Pmu { fds: Vec<Vec<RawFd>> }` (outer dim = counter,
  inner dim = CPU). Holds owned fds; `Drop` closes them.
- `pub fn open(nr_cpus: u16) -> Result<Self>` — calls `perf_event_open`
  for each (counter, cpu). Uses `perf-event-open-sys` (already a
  transitive dep via libbpf-rs ecosystem; check before adding) or raw
  `libc::syscall(SYS_perf_event_open, ...)` if not.
- `pub fn install(&self, skel: &mut OpenBpfSkel) -> Result<()>` — does
  `bpf_map__update_elem` on each of the four perf-event-array maps,
  keyed by cpu_id. Called between `scx_ops_open!` and `scx_ops_load!`
  in `Scheduler::init`.
- Errors during `open` for an individual (counter, cpu) are logged once
  at warn level and the fd is left as `-1`; the BPF map slot stays
  unset. Errors that affect every CPU for a given counter cause that
  whole counter to be skipped with a single info log.

`Scheduler::init` calls `Pmu::open` then `Pmu::install` before load. The
`Pmu` is owned by the same scope as `BpfSkel` so the fds outlive the
attached scheduler.

## BPF mechanics

In `src/bpf/main.bpf.c`:

- Declare four `BPF_MAP_TYPE_PERF_EVENT_ARRAY` maps:
  `pmu_instructions`, `pmu_cycles`, `pmu_l2_misses`, `pmu_stall_backend`.
  `max_entries = nr_cpus` (or a generous static upper bound).
- Helper:
  ```c
  static __always_inline u64 read_pmc(void *map, s32 cpu)
  {
      struct bpf_perf_event_value v = {};
      if (bpf_perf_event_read_value(map, cpu, &v, sizeof(v)) < 0)
          return 0;
      return v.counter;
  }
  ```
  We deliberately ignore `enabled`/`running` for now — multiplexing is
  not expected for four counters. Add scaling later if tooling shows
  divergence.
- `invariant_running`: replace the four placeholder zeros with a
  snapshot of all four counters into `tctx->pmc_*_start`, and replace
  `evt->cpu_perf = 0` with `evt->cpu_perf = scx_bpf_cpuperf_cur(cpu)`.
  (Per `<linux/sched/ext.h>`, `scx_bpf_cpuperf_cur` returns a value in
  `[0, SCX_CPUPERF_ONE]`; we store it as-is in `u16` — verify it fits;
  if it's a `u32`, mask the low bits and document the truncation.)
- `invariant_stopping`: replace the four placeholder zeros with
  `read_pmc(...) - tctx->pmc_*_start`.

No new event types, no new map slots in `task_ctx`, no scheduling-side
changes.

## Trace format impact

**None.** All four `pmc_*` fields and `cpu_perf` already exist in
`intf.h`; today's traces have them as literal zeros. After this change
the same fields carry real values. Older traces remain readable;
`reader.py` already decodes them with no changes required.

## Files in scope

- **New**: `scheds/rust/scx_invariant/src/pmu.rs` — perf event lifecycle
  and BPF map population.
- **Modified**: `scheds/rust/scx_invariant/src/bpf/main.bpf.c` — four
  perf-event-array maps, `read_pmc()` helper, real reads in
  `invariant_running` / `invariant_stopping`, `scx_bpf_cpuperf_cur()`
  call site.
- **Modified**: `scheds/rust/scx_invariant/src/main.rs` — `mod pmu;`,
  hook `Pmu::open` + `Pmu::install` between `scx_ops_open!` and
  `scx_ops_load!` in `Scheduler::init`.
- **Possibly modified**: `Cargo.toml` — `perf-event-open-sys` if not
  already transitively available.
- **Unchanged**: `src/bpf/intf.h`, `src/output.rs`, `analysis/reader.py`,
  `src/recorder.rs`, `src/cgroup.rs`. If any of these need to change,
  stop and document the rationale in `work/notes.md` per
  `docs/conventions.md`.

## Scheduling-behavior invariants

These must hold after the change (consistent with PLAN.md §13):

- `enqueue` remains the single-line passthrough into `SCX_DSQ_GLOBAL`.
- `select_cpu` continues to capture wakers without changing the
  scheduling decision.
- The PMU read path is gated by `is_target_task(p)` already at the top
  of `running` and `stopping`; no additional filter needed.
- No new BPF maps in the hot path other than the four perf-event-arrays
  read with O(1) helpers.

## Out of scope

- **EVT_TICK PMU snapshots** — Task 7. Don't add `ops.tick` here.
- **x86 / non-aarch64 event encodings** — initial drop targets the host
  this project runs on. Cross-arch event tables can come later.
- **Scaling for multiplexed counters** — capture `enabled`/`running`
  from `bpf_perf_event_read_value` if and when measurement shows
  multiplexing in practice; document why we trust the raw count today.
- **Process-attached perf events** — see rejected alternative B.
- **Trace format changes** — fields already exist.

## Validation gates

Per `work/plan.md` and `docs/eval.md`:

1. **Build**: `cargo check -p scx_invariant`, then
   `cargo build --profile ci --locked -p scx_invariant`.
2. **Format**: `cargo fmt --check` (no new diffs introduced;
   pre-existing diffs documented in `work/notes.md` are not regressions
   to address here).
3. **Smoke**: `sudo target/ci/scx_invariant record -o /tmp/pmu.scxi -- \
    stress-ng --cpu 4 --timeout 5`. Reader output (`analysis/reader.py
    /tmp/pmu.scxi`) must show non-zero `pmc_instructions`, `pmc_cycles`,
   `pmc_l2_misses` (any non-zero), and `pmc_stall_backend` (any
   non-zero) on at least one EVT_RUNNING and one EVT_STOPPING per CPU.
4. **Sanity**: derived IPC = `pmc_instructions / pmc_cycles` for any
   per-quantum sample falls in `[0.05, 8.0]`. Values outside that range
   on a CPU-bound workload indicate a wiring bug (wrong event, wrong
   units, or unscaled multiplexing).
5. **Cgroup-scope regression**: spawn-mode trace must still contain
   only the workload's PIDs (no PMU-related path leaked the gate).
6. **PMU-unavailable degradation**: with
   `sudo sysctl kernel.perf_event_paranoid=3` and no `CAP_PERFMON`, the
   recorder must start and produce a trace; PMU fields will be zero and
   a single warn-level log line must say so.
7. **System-wide regression**: running without spawn must keep working
   exactly as before — same magic, topology, non-zero events,
   populated process table.

## Documentation updates

- `scheds/rust/scx_invariant/PLAN.md` — flip Task 5 from "Pending" to
  "Done" in §9; update §2 ASCII diagram if it still shows `(planned)`
  next to PMU work; remove the "Future additions" bullet for
  `pmu.rs` in §8.
- `work/notes.md` — append the final event-encoding choices, what
  failed first, anything unexpected about `bpf_perf_event_read_value`
  semantics on this kernel, and any deviation from this task spec.
- `work/changelog.md` — concise entry: "PMU integration: per-quantum
  IPC / cache / stall counters in EVT_RUNNING and EVT_STOPPING;
  cpu_perf populated from `scx_bpf_cpuperf_cur()`."
