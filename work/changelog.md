# Work Changelog

Chronological record of completed changes.

## 2026-04-22: Task 7 follow-up — drop `is_target_task(p)` gate from `invariant_tick` (reviewer M1)

- Task: address reviewer M1 on the just-landed Task 7 hook —
  gating an empty body on `is_target_task(p)` runs a three-kfunc
  chain (`bpf_cgroup_from_id` + `bpf_task_under_cgroup` +
  `__free(cgroup)`) in spawn mode to produce a bool that is
  immediately discarded. The gate's job is to short-circuit work;
  with no work after it, the gate is cargo-culted cost.
- Files changed:
  - `scheds/rust/scx_invariant/src/bpf/main.bpf.c` — body of
    `invariant_tick` is now `(void)p;` (true no-op). Comment above
    the function tells future maintainers to add the
    `is_target_task(p)` gate when they add real work, with the
    rationale (gate exists to short-circuit, empty body has nothing
    to short-circuit) inline.
  - `work/notes.md` — appended follow-up section documenting the
    spec deviation per `work/task.md`'s "stop and document why in
    `work/notes.md` before proceeding further" clause. The deviation
    is purely a cost-correctness tightening; observable behavior is
    unchanged (hook is still inert), trace format unchanged, kernel
    ABI match unchanged.
- Trace format: unchanged. No PMU reads, no ringbuf reserve, no
  events emitted. `EVT_TICK = 5` stays reserved in `intf.h`.
- Risks or follow-ups:
  - When a future task adds real work to `invariant_tick`, the
    in-function comment must be honored: gate on `is_target_task(p)`
    before the work, exactly like the sibling callbacks.

## 2026-04-22: Task 7 — minimal `ops.tick()` plumbing (no-op hook)

- Task: reserve the kernel `ops.tick()` callback in the `scx_invariant`
  BPF scheduler without adding any recording behavior. Scope-cut from
  the original "periodic PMU snapshots for long-running quanta" wording
  to avoid creating a second PMU producer that would overlap Task 5's
  `running` / `stopping` path.
- Files changed:
  - `scheds/rust/scx_invariant/src/bpf/main.bpf.c` — added
    `invariant_tick(p)` matching the kernel ABI
    (`void (*tick)(struct task_struct *p)` per
    `kernel/sched/ext_internal.h:382`); body is `if (!is_target_task(p))
    return;` and nothing else. Wired `.tick = (void *)invariant_tick`
    into `SCX_OPS_DEFINE(invariant_ops, ...)` between `.running` and
    `.stopping` to mirror lifecycle order.
  - `scheds/rust/scx_invariant/PLAN.md` — §6 row marks `EVT_TICK` as
    Reserved (was Pending); §7 prose drops the "remaining optional
    addition" framing; §9 roadmap row reads "Minimal `ops.tick()` hook"
    / Done; recommended-next-order paragraph emptied.
  - `work/notes.md` — appended rescope rationale (PMU truth path stays
    in `running`/`stopping`; `tick()` is not a precise quantum boundary;
    hook is reserved for a separately-specified future design).
- Trace format: unchanged. `intf.h`, `output.rs`, `analysis/reader.py`,
  `recorder.rs`, `main.rs`, `pmu.rs`, `cgroup.rs` all untouched.
  `EVT_TICK = 5` stays reserved in `intf.h` for a future spec.
- Risks or follow-ups:
  - Hook is intentionally inert; if a future task wants to record at
    tick boundaries it must come with its own spec covering what is
    recorded, why it isn't covered by `running`/`stopping`, and the
    format-evolution plan for `EVT_TICK`.
  - One indirect call per kernel scheduler tick on each SCX-running CPU
    (vs. taking the `SCX_HAS_OP(sch, tick) == false` short-circuit
    branch). Negligible — see `work/notes.md` 2026-04-22 for the
    cost-of-hook check.

## 2026-04-20: Drop dead-branch `Option<Pmu>` (reviewer M2)

- Task: address reviewer M2 on the Task 5 PMU integration —
  `Scheduler._pmu: Option<pmu::Pmu>` advertised "PMU init may be
  absent" while the runtime path used `?` to hard-fail on init,
  contradicting `work/task.md` Approach D ("the recorder must
  always start, even with PMU disabled"). The `None` arm of the
  `Option` was unreachable by construction.
- Files changed:
  - `scheds/rust/scx_invariant/src/pmu.rs` — `Pmu::open` and
    `Pmu::install` are now infallible (`-> Self`, `-> ()`
    respectively). `Pmu::open` body was already failure-free; the
    `Result` return there was dead-branch and is just narrowed.
    `Pmu::install` now demotes `bpf_map_update_elem` errors
    (`ENOMEM`, `EINVAL`, `E2BIG`) to a per-counter warn log (one
    per counter at most, with the first error string and ok/failed
    counts) and leaves the failed slot unset — BPF reads return 0
    for that (counter, cpu), matching the per-CPU `perf_event_open`
    failure path. `pmu::open_and_install` becomes a two-line
    infallible wrapper. Dropped `anyhow::{Context, Result}` import
    (no longer used in this file).
  - `scheds/rust/scx_invariant/src/main.rs` — `Scheduler._pmu:
    pmu::Pmu` (was `Option<pmu::Pmu>`); doc-comment rewritten to
    explain the now-aligned type/runtime contract.
    `Scheduler::init` call site reduced to `let pmu =
    pmu::open_and_install(&skel, nr_cpus);` (no `?`, no
    `.context`). `anyhow::Context` import retained — still used
    by cgroup/topology/ctrlc setup elsewhere in the file.
- Behavior impact:
  - Happy path: identical (no observable change).
  - Unhappy path (`bpf_map_update_elem` failure on one or more
    CPUs): previously aborted the recorder. Now logs a single warn
    per affected counter (e.g. `"PMU counter 'cycles' map install:
    142 ok, 2 failed (...); failed CPUs will record 0"`) and the
    recorder continues. Failed (counter, cpu) slots produce zero
    in the trace, same semantics as the per-CPU
    `perf_event_open`-denied path.
- Validation performed:
  - `cargo check -p scx_invariant` (with touch on `main.bpf.c` to
    force BPF rebuild) — success, only the pre-existing
    `event_count` warning. Lints clean (ReadLints).
  - `cargo fmt --check` — five pre-existing diffs only
    (`cgroup.rs:83/133`, `main.rs:32/189`, `output.rs:71`); zero
    new diffs from this fix.
- Risks or follow-ups:
  - The `info!("PMU events installed for {} CPUs", nr_cpus)` log
    in `Scheduler::init` may now read as misleading when
    `Pmu::install` partially failed (the per-counter warn already
    surfaces that, but a reader scanning only info-level logs
    might miss it). Left as-is; documented in `work/notes.md`.
  - Runtime gates from `work/task.md` (smoke + IPC sanity, plus
    explicit gate 6 — paranoid=3, no CAP_PERFMON degradation
    test) still owed by the operator before merge. M2 makes
    gate 6 strictly more achievable since map-install failures
    no longer abort either.

## 2026-04-20: Reserved-zero pmc_* in evt_running (reviewer M1)

- Task: address reviewer M1 on the Task 5 PMU integration —
  `evt_running.pmc_*` carried raw start-of-quantum CPU lifetime
  snapshots while `evt_stopping.pmc_*` carried per-quantum deltas.
  Same field name, two physical units in a shared on-disk format.
  A naive "sum pmc_instructions across all events" aggregator would
  silently double-count.
- Files changed:
  - `scheds/rust/scx_invariant/src/bpf/main.bpf.c` —
    `invariant_running` still calls `read_pmc()` for all four
    counters and stores the snapshots in `tctx->pmc_*_start` (still
    needed by `invariant_stopping` for the delta), but now writes
    **zeros** into `evt->pmc_*` instead of the raw snapshots.
    `evt->cpu_perf` stays populated (it's a normalized standalone-
    meaningful value, not a counter). Surrounding comment block
    rewritten to lock in the contract: pmc_* deltas live exclusively
    in evt_stopping; future maintainers must not start populating
    evt_running's pmc_* slots.
  - `scheds/rust/scx_invariant/src/bpf/intf.h` — `evt_running`'s
    four `pmc_*` fields documented as RESERVED-ZERO with the full
    rationale; one-line comment added to `cpu_perf` clarifying its
    [1, SCX_CPUPERF_ONE] range.
  - `scheds/rust/scx_invariant/analysis/reader.py` — "Sample PMU
    Events" block previously sampled the first 3 RUNNING events with
    non-zero `pmc_cycles`, which would never trigger after this
    change. Now samples first 3 RUNNING events with non-zero
    `cpu_perf` and prints `cpu_perf` only (no `pmc_*`). STOPPING
    samples and the aggregate tables (PMU Summary, Top 20 by
    Instructions Retired) are unchanged — they were already
    correctly sourced from STOPPING only.
- Behavior impact:
  - On-disk format unchanged; payload sizes identical.
  - `evt_running.pmc_*` is always zero in new traces. Older traces
    remain readable; the updated reader ignores those slots.
  - No double-counting risk in any future "iterate all events" sum.
  - `evt_stopping.pmc_*` (the per-quantum deltas) and
    `evt_running.cpu_perf` are unaffected.
- Validation performed:
  - `cargo check -p scx_invariant` (with touch on `main.bpf.c` and
    `intf.h` to bypass the cargo build-script fingerprint cache) —
    success, only the pre-existing `event_count` warning. BPF
    recompiled.
  - `python3 -c "import ast; ast.parse(...)"` on reader.py — OK.
- Risks or follow-ups:
  - Any third-party reader that opportunistically diffed
    evt_running.pmc_* across event pairs on the same CPU loses that
    capability. Such a reader was already incorrect (cross-task /
    cross-time interleaving misattributes work) — strictly an
    improvement.
  - Runtime gates from `work/task.md` (smoke + IPC sanity) still
    owed by the operator before merge.

## 2026-04-20: Saturating PMC delta (reviewer H1, post-Task-5)

- Task: address reviewer block H1 on the Task 5 PMU integration —
  u64 underflow in `evt->pmc_*` when `read_pmc()` returns 0 at
  `invariant_stopping` while `tctx->pmc_*_start` was non-zero.
  Failure modes: transient `bpf_perf_event_read_value` failure
  (multiplexing pause, ARM PMU power-state, any kfunc < 0), or
  `running` skipped while `stopping` fires due to kernel
  SCX_TASK_QUEUED pairing race. Naive subtraction wraps to ~1.84e19
  and poisons any downstream aggregator.
- Files changed:
  - `scheds/rust/scx_invariant/src/bpf/main.bpf.c` — added
    `static __always_inline u64 sat_sub(u64 end, u64 start)` next to
    `read_pmc()`; `invariant_stopping` calls `sat_sub()` for all four
    `pmc_*` delta writes; updated the surrounding comment block to
    enumerate both failure modes the helper guards against.
- Behavior impact:
  - When `end < start`, the trace records `0` for that counter delta
    instead of ~UINT64_MAX. Same semantics as the start-side
    "counter unavailable" path, so the reader treats both as "no PMU
    data this quantum".
  - No format change. Happy-path values unchanged. No verifier risk
    (compare + branch only).
  - The stale-`tctx` desync case (case 2 in `work/notes.md`) is only
    partly addressed — `sat_sub` kills the underflow but not the
    stale-start inflation. Proper fix is a per-quantum generation
    bit on `task_ctx`; deferred per `work/notes.md`.
- Validation performed:
  - `cargo check -p scx_invariant` — success, only the pre-existing
    `event_count` warning. BPF recompiled (touched the .c to bypass
    cargo's build-script fingerprint cache).
- Risks or follow-ups:
  - Generation-bit fix for the stale-`tctx` case (also affects
    pre-existing `runtime_ns` inflation; better fixed in one pass).
  - Optional percpu counter for sat-sub trigger rate, to spot any
    real-world cases in production.
  - Runtime gates from `work/task.md` (smoke + IPC sanity) still
    owed by the operator before merge — same as the original Task 5
    handoff.

## 2026-04-20: PMU integration (Task 5)

- Task: per-quantum hardware-counter deltas in EVT_RUNNING / EVT_STOPPING
  plus real `cpu_perf` from `scx_bpf_cpuperf_cur()`. Replaces the four
  `pmc_*` zero placeholders (`main.bpf.c:199,203-206,245-248` pre-task)
  with system-wide CPU-pinned `perf_event_open` reads via four BPF
  perf-event-array maps. Trace format unchanged — slots already existed.
- Files changed:
  - `scheds/rust/scx_invariant/src/pmu.rs` (new, ~170 LOC) — `Pmu`
    holding owned per-(counter, cpu) fds, `Pmu::open(nr_cpus)` that
    swallows per-CPU and per-counter open failures with one log each,
    `Pmu::install(&BpfSkel)` that pushes fds into the four perf-event
    arrays, and `pmu::open_and_install(skel, nr_cpus)` convenience
    wrapper. Uses `scx_utils::perf` (already a workspace dep) for the
    `perf_event_open` syscall and bindings.
  - `scheds/rust/scx_invariant/src/bpf/main.bpf.c` — four
    `BPF_MAP_TYPE_PERF_EVENT_ARRAY` maps (`pmu_instructions`,
    `pmu_cycles`, `pmu_l2_misses`, `pmu_stall_backend`) with
    `max_entries = SCX_INVARIANT_MAX_CPUS = 1024` (generous static
    upper bound); `read_pmc()` helper using
    `bpf_perf_event_read_value` with errors mapped to 0;
    `invariant_running` now snapshots all four counters into the
    pre-existing `tctx->pmc_*_start` slots and writes
    `evt->cpu_perf = (u16)scx_bpf_cpuperf_cur(cpu)` plus the start
    values into `evt_running`'s `pmc_*` fields; `invariant_stopping`
    now writes per-quantum deltas (`end - start`).
  - `scheds/rust/scx_invariant/src/main.rs` — `mod pmu;`, `Scheduler`
    gains `_pmu: Option<pmu::Pmu>`, `Scheduler::init` takes a
    `nr_cpus: u16` parameter and runs `pmu::open_and_install` between
    `scx_ops_load!` and `scx_ops_attach!`, single call-site update
    in `main()`.
  - `scheds/rust/scx_invariant/PLAN.md` — Task 5 flipped to Done in
    §9 roadmap, recommended-next-order list trimmed to Task 7, §2
    diagram drops `(planned)` next to `runnable` / `quiescent` /
    `select_cpu`, §8 Future-additions block reframed as "now in tree".
- Behavior impact:
  - Trace files now carry **real** PMU counts in EVT_RUNNING (start
    snapshots) and EVT_STOPPING (per-quantum deltas). Older traces
    where these fields were zero remain readable; reader.py needs no
    changes.
  - `evt_running.cpu_perf` is no longer zero — populated from
    `scx_bpf_cpuperf_cur(cpu)` in [1, 1024] (SCX_CPUPERF_ONE).
  - On a host without PMU access (`perf_event_paranoid >= 2` and no
    `CAP_PERFMON`), the recorder still starts and records zeros for
    PMU fields — single info log per failed counter, single warn log
    if a counter is partially available.
  - No scheduling policy changes; `enqueue` still passthrough to
    `SCX_DSQ_GLOBAL`, `select_cpu` still returns `prev_cpu`. All PMU
    reads are gated by the existing `is_target_task(p)` check at the
    top of `running` / `stopping`.
- Deviation from `work/task.md`:
  - task spec puts `Pmu::install` between `scx_ops_open!` and
    `scx_ops_load!`. That can't work — `bpf_map_update_elem` needs a
    real map fd, which only exists post-load. Moved to between
    `scx_ops_load!` and `scx_ops_attach!`, matching what
    `scx_layered::create_perf_fds` and `scx_cosmos::setup_perf_events`
    do. Maps are still populated before any callback can fire.
    Rationale documented in `work/notes.md` 2026-04-20 PMU entry.
- Validation performed:
  - `cargo check -p scx_invariant` — success, 1 pre-existing
    `event_count` warning.
  - `cargo build --profile ci --locked -p scx_invariant` — success
    (BPF compiled, four perf-event-array maps and `read_pmc` linked).
  - `cargo fmt -p scx_invariant -- --check` — five pre-existing diffs
    only (`cgroup.rs:83`, `cgroup.rs:133`, `main.rs:32`,
    `main.rs:189`, `output.rs:71`); none introduced by this task.
  - Cross-checked `scx_bpf_cpuperf_cur` return type and range against
    `kernel/sched/ext.c:9076` and `kernel/sched/ext_internal.h:20`
    in `~/upstream-kernel`; verified `SCHED_CAPACITY_SCALE = 1024`
    fits u16. Verified ARMv8 PMUv3 event codes
    (`L2D_CACHE_REFILL=0x17`, `STALL_BACKEND=0x24`) against
    `include/linux/perf/arm_pmuv3.h`. Verified `armv8_pmuv3_0` is
    present under `/sys/bus/event_source/devices/`.
- Risks or follow-ups:
  - Runtime validation gates 3–7 in `work/task.md` (smoke run with
    stress-ng, IPC sanity, PMU-unavailable degradation, cgroup-scope
    regression, system-wide regression) require sudo + a sched_ext-
    capable kernel and were not run from the sandbox. Owed by the
    operator before merge.
  - x86 / non-aarch64 event encodings intentionally out of scope per
    task spec.
  - Multiplexing scaling deferred until measurement shows divergence;
    `read_pmc()` already uses `bpf_perf_event_read_value` so
    `enabled`/`running` are available without an ABI change.

## 2026-04-20: Implement userspace half of cgroup filtering (Task 3, spawn-only)

- Task: deliver the userspace half of `work/task.md` (cgroup-based
  process-tree filtering). BPF gate, rodata, and `is_target_task(p)` were
  already in tree from the 2026-04-17 pass; this change adds the cgroup
  lifecycle, CLI surface, rodata wiring, and workload-exit shutdown.
- Mid-task scope reduction: attach mode (`--cgroup <path>` against an
  existing cgroup) was cut. Only spawn mode and system-wide remain. All
  attach-related code/CLI surface was removed in the same session before
  handoff (see `work/notes.md` 2026-04-20). BPF still supports attach by
  inode id, so reintroducing it later is a thin userspace addition.
- Files changed:
  - `scheds/rust/scx_invariant/src/cgroup.rs` (new) — `Cgroup` with
    `create_temporary` / `procs_path` / `cgid`, unconditional Drop-time
    rmdir, plus `ensure_cgroup_v2_unified` guard using `statfs(2)`
    `f_type == CGROUP2_SUPER_MAGIC`.
  - `scheds/rust/scx_invariant/src/main.rs` — added `record` subcommand
    with two modes (spawn, system-wide), a `Mode` enum, `resolve_mode()`,
    rodata wiring in `Scheduler::init` between `scx_ops_open!` and
    `scx_ops_load!`, `spawn_workload` with child-side `pre_exec` writing
    `b"0\n"` to `cgroup.procs` (async-signal-safe, raw libc), and
    `spawn_child_watcher` thread that flips the existing shutdown
    `AtomicBool` when the workload exits. The pre-task-3 top-level
    `scx_invariant -o file.scxi` form is preserved as legacy
    system-wide.
  - `scheds/rust/scx_invariant/PLAN.md` — Task 3 flipped to Done in the
    roadmap table (with attach-deferred note); §12 build/run examples now
    show `record -- cmd` alongside the legacy form.
- Behavior impact:
  - System-wide recording behavior is unchanged (`record` with no command
    or the legacy top-level `-o` invocation).
  - `record -o trace.scxi -- <cmd>`: creates `/sys/fs/cgroup/scx_invariant-<pid>`,
    spawns the workload into it via child-side `pre_exec`, records until
    the workload exits, then rmdirs the cgroup (best-effort, log on fail).
  - Cgroup-v1-only / hybrid `/sys/fs/cgroup` mounts are refused with a
    clear error per task spec.
  - Spawn exit code is always 0 on a successful trace; workload's own exit
    status is logged for visibility.
- Validation performed:
  - `cargo check -p scx_invariant` — success, 1 warning (pre-existing
    `output.rs::event_count`). All cgroup-module symbols are now used.
  - `cargo build -p scx_invariant` — success.
  - `cargo fmt --check` — only the three pre-existing diffs (`main.rs:31`,
    `main.rs:138`, `output.rs:71`) noted in `work/notes.md`. No new diffs.
  - CLI smoke-tested without root: legacy top-level form, `record` with
    no flags, `record -o`, `record -- cmd`, and `record --cgroup` (now
    rejected by clap as unknown) all behave as expected.
  - Negative paths exercised: non-root spawn → "create_dir(/sys/fs/cgroup/scx_invariant-<pid>) failed".
- Risks or follow-ups:
  - Runtime validation under root + real workload (validation gates 3-6
    in `work/task.md`) still owed by the operator — this required `sudo`
    plus a working sched_ext-capable kernel and was not run from the
    sandbox.
  - Attach mode is intentionally deferred; revisit only if a real use
    case shows up.
  - Hybrid mounts (v2 at `/sys/fs/cgroup/unified`) intentionally
    rejected; if needed later, add a `--cgroup-root` flag rather than
    auto-discovery.

## 2026-04-16: Implement runnable/quiescent/select_cpu hooks

- Task: Add three profiling hooks to scx_invariant
- Files changed:
  - `scheds/rust/scx_invariant/src/bpf/main.bpf.c` — added `invariant_select_cpu`, `invariant_runnable`, `invariant_quiescent`; updated `invariant_running` to populate waker fields from `task_ctx` and reset after use; registered all three in `SCX_OPS_DEFINE`
  - `scheds/rust/scx_invariant/analysis/reader.py` — added `RUNNABLE_FMT`/`QUIESCENT_FMT` struct decoders, `parse_event()` cases for EVT_RUNNABLE/EVT_QUIESCENT, sleep duration analysis section, updated wakeup graph message
- Behavior impact:
  - New RUNNABLE events with sleep_duration_ns (computed from quiescent→runnable delta)
  - New QUIESCENT events with deq_flags
  - evt_running now carries waker_pid, waker_tgid, wake_flags (populated via select_cpu)
  - select_cpu returns prev_cpu (passthrough, no policy change)
  - reader.py prints sleep duration top-20 and wakeup edge graph
- Validation performed:
  - `cargo build --profile ci --locked -p scx_invariant` — success (1 pre-existing warning)
  - 3-second runtime capture on 144-CPU aarch64 (kernel 6.17.0-1016-nvidia-64k)
  - reader.py parsed trace: 11 RUNNING, 9 STOPPING, 11 RUNNABLE, 9 QUIESCENT events
  - Wakeup graph populated with correct waker→wakee edges
  - Sleep duration analysis showing per-thread totals and averages
- Risks or follow-ups:
  - Pre-existing `runq_wait_ns` inflation at scheduler attach (not introduced by this task)
  - Pre-existing `cargo fmt` diffs in main.rs/output.rs (not introduced by this task)
