# scx_invariant — Project Plan & Architecture

This document is the authoritative overview of the scx_invariant project for
agents and contributors. It captures **what we are building, how it is
structured, what is done, and what remains**. Diagrams are explicit so the
data flow can be understood without reading source code.

---

## 1. What scx_invariant Is

scx_invariant is a **sched_ext passthrough scheduler** that records every
scheduling transition for a target workload, producing a binary trace file
(`.scxi`) for offline analysis.

It is a **passthrough observer**: it delegates all scheduling decisions to
default sched_ext behavior (global FIFO DSQ). It makes no scheduling decisions
of its own. Its only job is to record events with minimal perturbation.

### Why "invariant"

Phase 1 captures **scheduler-invariant workload identity** — properties of a
workload that do not depend on which scheduler is running:

- **Wakeup graph topology** (who wakes whom, sync vs async)
- **Computational character per task** (IPC, cache behavior, pipeline stalls)
- **Phase structure** (which phases exist, their sequence)
- **Task lifecycle** (which threads exist, when they spawn and exit)
- **Blocking patterns** (voluntary sleep frequency, sleep durations)

These are the workload's intrinsic behavior, stripped of scheduler opinion.
To explain why scheduler X beat scheduler Y on a workload, you first need to
know **what the workload IS** — that is what this tool captures.


### Long-term scope

Phase 1 records the **full event stream** — every scheduling transition for
every task in the target scope, with all annotations the BPF callbacks can
reach (timestamps, CPU, slice usage, wakeup attribution, PMU counters, etc.).
The goal is to capture **everything** about each task's scheduling behavior
so nothing has to be re-collected later. **Analysis is explicitly out of scope
for Phase 1** — it is a separate phase that consumes the `.scxi` traces
offline. The reader (`analysis/reader.py`) ships a minimal summary purely to
validate the data pipeline; real analysis (workload fingerprinting, phase
detection, scheduler diffs) waits until the next phase.


---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Target workload (process tree, scheduled normally)                  │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              │ scheduling transitions
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│  BPF Kernel Side  (src/bpf/main.bpf.c)                               │
│  ─────────────────────────────────────                               │
│  ops.enqueue    → SCX_DSQ_GLOBAL  (passthrough, no decision)         │
│  ops.running    → emit EVT_RUNNING                                   │
│  ops.stopping   → emit EVT_STOPPING                                  │
│  ops.runnable   → (planned) emit EVT_RUNNABLE                        │
│  ops.quiescent  → (planned) emit EVT_QUIESCENT                       │
│  ops.select_cpu → (planned) capture waker into wakees task_ctx       │
│  ops.tick       → (planned) emit EVT_TICK with PMU snapshot          │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              │ raw event bytes
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│  6 BPF Ring Buffers  (32 MB each, route by cpu_id % 6)               │
│    events_rb_0  events_rb_1  events_rb_2                             │
│    events_rb_3  events_rb_4  events_rb_5                             │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              │ poll(1ms), BPF_RB_NO_WAKEUP
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Rust Userspace                                                      │
│  ──────────────                                                      │
│  recorder.rs  →  RingBufferBuilder polls all 6 buffers               │
│                  Receives &[u8] (raw event bytes)                    │
│                                                                      │
│  output.rs    →  Hot-path writer                                     │
│                  Write [type:u16][len:u16][raw bytes]                │
│                  through 256 KB BufWriter                            │
│                                                                      │
│  No decoding. No analysis. Just raw bytes to disk.                   │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                  ┌─────────────────────┐
                  │  .scxi binary file  │
                  └─────────────────────┘
                              │
                              │ (offline)
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Python Reader  (analysis/reader.py)                                 │
│  ───────────────────────────                                         │
│  Parses sections (header, topology, events, process table)           │
│  Decodes events using struct.unpack                                  │
│  Prints summaries:                                                    │
│    - File info (host, arch, CPUs, duration, event count)             │
│    - Topology by NUMA node                                           │
│    - Per-thread top 20 by runtime                                    │
│    - Migrations, voluntary/preempted ratio                           │
│    - (planned) wakeup graph, IPC distributions, phase detection      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Hot Path vs Cold Path

The system is split into two layers with deliberately different constraints:

| Layer | Path | Constraint | Implementation |
|-------|------|------------|----------------|
| BPF callbacks | Hot | Microseconds budget; cannot perturb scheduling | Minimal C, fixed-size structs |
| Ring buffer + writer | Hot | Must keep up with millions of events/sec | Raw bytes, BufWriter, no decoding |
| Python reader | Cold | Runs offline, can take its time | struct.unpack, easy to iterate |

The hot path goal is **< 2-3% overhead** under heavy scheduling load. Decoding,
analysis, and human-readable output all happen offline.

---

## 4. Per-Event Data Flow

```
 1. Task A starts running on CPU 17
        │
        ▼
 2. Kernel calls invariant_running(A)
        │
        ▼
 3. BPF reads scx_bpf_now(), p->pid, p->tgid, scx_bpf_task_cpu()
        │
        ▼
 4. BPF calls rb_reserve(17 % 6 = 5)  →  reserves 88 bytes in events_rb_5
        │
        ▼
 5. BPF fills evt_running struct in place
        │
        ▼
 6. BPF calls bpf_ringbuf_submit(BPF_RB_NO_WAKEUP)
        │
        ▼  (event sits in ring buffer until consumer polls)
        │
 7. Userspace polls events_rb_5 every 1ms via libbpf-rs
        │
        ▼
 8. libbpf-rs calls handle_event(&[u8; 88])
        │
        ▼
 9. output.rs reads event_type from offset 20 of the bytes
        │
        ▼
10. Writes [type=1: u16][len=88: u16][88 raw bytes] to BufWriter
        │
        ▼  (BufWriter flushes to disk in 256 KB chunks)
        │
11. .scxi file grows on disk
```

Note: **no decoding happens during recording**. The Python reader does all
decoding offline.

---

## 5. .scxi Binary File Format

```
┌──────────────────────────────────────────────────────────┐
│  File Header (64 bytes, fixed)                           │
│  ──────────────────────────────                          │
│    offset  0:  magic = "SCXI"     (4 bytes)              │
│    offset  4:  version             (u16)                 │
│    offset  6:  header_size         (u16)                 │
│    offset  8:  flags               (u32)                 │
│    offset 12:  timestamp_start_ns  (u64)                 │
│    offset 20:  timestamp_end_ns    (u64, filled at exit) │
│    offset 28:  hostname            (28 bytes)            │
│    offset 56:  kernel_version      (u32)                 │
│    offset 60:  arch                (u16, 1=aarch64)      │
│    offset 62:  nr_cpus             (u16)                 │
├──────────────────────────────────────────────────────────┤
│  Topology Section (section_type = 0x0001)                │
│  ──────────────────────────────                          │
│    section_type (u16) + section_len (u32)                │
│    Per-CPU entries (16 bytes each):                      │
│      cpu_id (u16), llc_id (u16), numa_id (u16),          │
│      max_freq_mhz (u16), capacity (u32), pad (u32)       │
├──────────────────────────────────────────────────────────┤
│  Events Section (section_type = 0x0003)                  │
│  ──────────────────────────────                          │
│    section_type (u16) + section_len (u32 = 0)            │
│    Packed events, each is:                               │
│      [event_type: u16][payload_len: u16][raw bytes]      │
│    Reader can skip unknown event types by jumping        │
│    payload_len bytes forward (forward-compatible).        │
├──────────────────────────────────────────────────────────┤
│  Process Table (section_type = 0x0002, at finalize)      │
│  ──────────────────────────────                          │
│    section_type (u16) + section_len (u32)                │
│    Per-pid entries (20 bytes each):                      │
│      pid (u32), comm (16 bytes ASCII)                    │
│    Written after events stop, from PIDs seen in trace.   │
└──────────────────────────────────────────────────────────┘
```

**Known issue**: event type IDs (1-5) collide with section type IDs (0x0001
through 0x0003). The reader uses payload-size heuristics to disambiguate. Fix
in v2 by renumbering event types to start at 0x0100.

---

## 6. Event Types

Defined in `src/bpf/intf.h`. Common header is 24 bytes:

```c
struct scx_invariant_event {
    u64 timestamp_ns;   // offset 0
    u32 pid;            // offset 8
    u32 tgid;           // offset 12
    u32 cpu;            // offset 16
    u16 event_type;     // offset 20
    u16 flags;          // offset 22
};
```

| Type | Value | Total Size | Purpose | Status |
|------|-------|-----------:|---------|--------|
| EVT_RUNNING | 1 | 88 B | Task started executing on a CPU | Done |
| EVT_STOPPING | 2 | 88 B | Task stopped executing | Done |
| EVT_RUNNABLE | 3 | 40 B | Task became runnable (woke up) | Done |
| EVT_QUIESCENT | 4 | 32 B | Task went to sleep | Done |
| EVT_TICK | 5 | 64 B | Periodic PMU snapshot during long quantum | Pending |

Flags (`scx_invariant_event.flags`):
- `FLAG_MIGRATED` (1<<0) — task is on a different CPU than last run
- `FLAG_SYNC_WAKEUP` (1<<1) — wakeup carried WF_SYNC
- `FLAG_VOLUNTARY` (1<<2) — voluntary context switch (task slept)

---

## 7. Task Lifecycle State Machine

Each task moves through these states. Each transition is an event we record.

```
                  ┌─────────────┐
                  │  Sleeping   │
                  └─────────────┘
                        │ wakeup
       EVT_RUNNABLE  ←──┤
                        ▼
                  ┌─────────────┐
                  │  Runnable   │
                  └─────────────┘
                        │ scheduled onto CPU
       EVT_RUNNING   ←──┤
                        ▼
                  ┌─────────────┐
                  │   Running   │ ←── EVT_TICK (periodic, optional)
                  └─────────────┘
                        │ preempted or yielded
       EVT_STOPPING  ←──┤
                        ▼
              ┌─────────┴─────────┐
              │                   │
        runnable=true       runnable=false
              ▼                   ▼
       back to Runnable    Quiescent (sleeping)
                                  │
                       EVT_QUIESCENT ←
```

All four state-transition events (`EVT_RUNNING`, `EVT_STOPPING`, `EVT_RUNNABLE`,
`EVT_QUIESCENT`) are now recorded. `EVT_TICK` for periodic PMU snapshots during
long quanta is the remaining optional addition (Task 7).

---

## 8. File Layout

```
~/scx/scheds/rust/scx_invariant/
├── Cargo.toml
├── build.rs                    # invokes scx_cargo to compile BPF
├── src/
│   ├── main.rs                 # CLI, BPF lifecycle, signal handling
│   ├── recorder.rs             # ring buffer poll loop
│   ├── output.rs               # binary file writer (HOT PATH)
│   ├── bpf_skel.rs             # auto-generated by build.rs
│   ├── bpf_intf.rs             # auto-generated by build.rs
│   └── bpf/
│       ├── intf.h              # shared C types (BPF + Rust + Python)
│       └── main.bpf.c          # BPF program: sched_ext_ops callbacks
└── analysis/
    └── reader.py               # Python parser for .scxi files
```

Future additions (planned tasks):

```
└── src/
    ├── cgroup.rs               # cgroup setup + filtering (Task 3)
    └── pmu.rs                  # perf_event_open + PMU map setup (Task 5)
```

---

## 9. Implementation Status & Roadmap

| # | Task | What it adds | Status |
|---|------|--------------|--------|
| 1 | Project scaffolding + bare passthrough | enqueue → global DSQ; Rust load/attach | Done |
| 2 | EVT_RUNNING / EVT_STOPPING | running/stopping callbacks; 6 ring buffers; recorder.rs | Done |
| 2.5 | Binary writer + Python reader | output.rs, .scxi format, reader.py — full pipeline | Done |
| 3 | Cgroup filtering | bpf_task_under_cgroup() filter; cgroup.rs auto-setup | Pending |
| 4a | Sleep durations | runnable + quiescent callbacks; EVT_RUNNABLE/EVT_QUIESCENT | Done |
| 4b | Wakeup attribution | select_cpu callback; waker fields in EVT_RUNNING | Done |
| 5 | PMU integration | perf_event_open per CPU; PMU reads in running/stopping; also populate `cpu_perf` from `scx_bpf_cpuperf_cur()` | Pending |
| 7 | Tick recording | ops.tick() callback; periodic PMU snapshots | Pending |

**Recommended next order** for the remaining work:

1. **Task 3 — Cgroup filtering** (highest priority). Without scoping, every
   recording is system-wide, producing hundreds of MB of irrelevant events for
   small target workloads. The PLAN.md analysis layer assumes a PID tree; we
   should stop recording outside that tree at the source.
2. **Task 5 — PMU integration**. Fills in `pmc_instructions`, `pmc_cycles`,
   `pmc_l2_misses`, `pmc_stall_backend` (currently zero) and populates
   `cpu_perf` from `scx_bpf_cpuperf_cur()`. Unlocks IPC / stall / migration-cost
   analysis in the reader.
3. **Task 7 — Tick recording**. Periodic PMU snapshots for long-running
   quanta. Optional; benefits CPU-bound workloads that rarely hit
   running/stopping.

Tasks 4a and 4b were implemented together in commit `139b7850` along with a
fix for a first-run false-migration bug (`last_cpu >= 0` passed trivially on
zero-initialized task storage).

---

## 10. Final Goal — Per-Task & Per-Workload Analysis

scx_invariant is Phase 1 of a larger effort. The eventual deliverable is an
**analysis layer** that consumes `.scxi` traces and answers detailed questions
about application behavior. Given an application's PID (and its whole
process tree, via the Task 3 cgroup scoping), the analysis tool should be able
to characterize every aspect of that application at the scheduler level.

### Per-Task Analysis

For every thread in the workload:

- Full timeline of state transitions (sleeping → runnable → running → stopping → ...)
- Runqueue wait time distribution (p50 / p90 / p99, histogram)
- Per-quantum runtime distribution
- Migration history — which CPUs, how often, cross-LLC / cross-NUMA breakdown
- Voluntary vs involuntary context-switch ratio
- Slice utilization — how much of the allocated slice was actually used
- Per-quantum PMU profile — IPC, L2 miss rate, backend stall breakdown
- Sleep duration distribution — how long the thread blocks. The "on what signal"
  detail (futex address, IO fd, etc.) requires tracking syscalls or blocker state
  beyond sched_ext callbacks and is deferred to a Phase 2 expansion.

### Per-Workload Analysis

For the application as a whole (all threads / processes in the PID tree):

- **Wakeup graph** — directed graph of "thread A wakes thread B" edges with
  frequencies, sync vs async classification, latency per edge
- Communication patterns — producer/consumer chains, fan-in / fan-out hubs
- Phase detection — distinct behavioral segments over time
- Aggregate IPC and stall accounting across threads
- Load balance across CPUs / NUMA nodes
- Bottleneck identification — which thread's wait time dominates?

### Visualizations

The analysis should produce visual artifacts, not just text:

- Per-thread swim-lane timelines (run / sleep / wait states over time)
- Wakeup graph rendered via dot / graphviz
- Latency and runtime histograms
- Per-CPU activity heatmaps
- Phase transition markers on the timeline
- Side-by-side diff view when multiple traces are given (e.g., same workload
  under different schedulers)

### Example question the analysis should answer

> *"I ran PostgreSQL pgbench. Why is p99 latency worse than expected?"*

Given the application PID tree, the analyzer should surface:

- Backend thread 5678 is waiting 340 µs on the runqueue 94 % of the time.
- Its waker is thread 1234 (pgbench client), firing 4,700 wakeups/sec.
- Post-wakeup, it migrates cross-LLC on 42 % of runs, costing ~180 L2 refills each.
- The scheduler is putting the wakee on the same CPU as the waker under
  SCX_WAKE_SYNC, but the waker has just gone quiescent — leaving the wakee
  on a cold CPU.

Phase 1 captures the raw event stream that makes this analysis possible. The
analyzer itself is the payoff.

---

## 11. Key Design Decisions

### Why passthrough FIFO?

The scheduler delegates all decisions to global FIFO. We do not make scheduling
decisions. This minimizes perturbation and gives a "neutral baseline" view of
the workloads intrinsic behavior.

### Why 6 ring buffers?

`BPF_MAP_TYPE_RINGBUF` has a single producer-side spinlock. On a 144-core
machine producing millions of events/sec, that lock causes severe cacheline
bouncing. Six buffers (cpu_id % 6) reduce contention to ~24 cores per lock.

### Why BPF_RB_NO_WAKEUP?

At 1M+ events/sec, per-event wakeup IPIs to userspace would dominate overhead.
Userspace polls every 1ms instead — events are picked up within 1ms with zero
notification cost.

### Why hot path / cold path split?

The recording side must be fast (BPF callbacks fire millions of times/sec).
The analysis side runs offline and benefits from rapid iteration. Python is
ideal for the latter — `struct.unpack` makes binary parsing trivial, no
compilation cycle when adding new analysis.

### Why TLV event framing in the file?

Each event has `[type: u16][len: u16]` prefix before its payload. This makes
the format **forward-compatible**: a reader can skip event types it does not
understand by jumping `len` bytes forward.

---

## 12. Build & Run

Currently on aarch64 Neoverse V2, 144 CPUs, kernel 6.17.

```bash
# One-time: ensure rustup toolchain is on PATH (rustc 1.94+ required)
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install stable

# Build
cd ~/scx
cargo build --release -p scx_invariant

# Record (system-wide for now; cgroup filtering comes in Task 3)
sudo ~/scx/target/release/scx_invariant -o /tmp/test.scxi
# Ctrl+C after a few seconds

# Read back
python3 ~/scx/scheds/rust/scx_invariant/analysis/reader.py /tmp/test.scxi
```

Sanity check (per `docs/eval.md`):
- Output prints "SCXI" magic and a sane header
- Topology section lists all CPUs
- Event count is non-zero
- Process table is non-empty

---

## 13. Constraints for Contributors

Per `docs/conventions.md`:

- Stay inside `scheds/rust/scx_invariant/`. Modifying anything else needs
  justification in `work/notes.md`.
- The scheduler **must remain a passthrough**. No scheduling decisions.
- Trace format changes must be synchronized across **three files**:
  `src/bpf/intf.h`, `src/output.rs`, `analysis/reader.py`.
- Per-event BPF logic must stay short to keep verifier happy and overhead low.

---

## 14. References

- Spec: `docs/superpowers/specs/2026-04-14-scx-invariant-design.md`
- Plan: `docs/superpowers/plans/2026-04-14-scx-invariant.md`
- Conventions: `docs/conventions.md`
- Eval: `docs/eval.md`
- Glossary: `docs/glossary.md`
