# Work Notes

## Task interpretation

Implement three profiling hooks: `runnable`, `quiescent`, `select_cpu`. All profiling-only — no scheduling policy changes. `select_cpu` returns `prev_cpu` (passthrough). Waker data flows through `task_ctx` from `select_cpu` into the `running` event.

## Relevant files and code paths

- `src/bpf/main.bpf.c` — BPF hooks (primary change)
- `src/bpf/intf.h` — event structs (already had `evt_runnable`, `evt_quiescent` defined; no changes needed)
- `src/output.rs` — generic TLV writer (no changes needed, handles any event type)
- `src/recorder.rs` — ring buffer consumer (no changes needed)
- `analysis/reader.py` — trace parser (added struct decoders + sleep/wakeup analysis)

## Design decisions

1. **`select_cpu` returns `prev_cpu`**: Simplest passthrough. The enqueue path already handles dispatch via `SCX_DSQ_GLOBAL`. No idle-CPU search logic added.

2. **Waker data flow**: `select_cpu` stores waker PID/TGID/wake_flags in wakee's `task_ctx`. `running` reads them into `evt_running` fields, then zeroes them to prevent stale propagation.

3. **`BPF_LOCAL_STORAGE_GET_F_CREATE`**: Used in `select_cpu` and `runnable` since these may be the first hooks to see a task. `quiescent` uses flag 0 since storage always exists by that point (created by `running`).

4. **`deq_flags` truncation**: Kernel passes `u64 deq_flags` but `evt_quiescent.deq_flags` is `u32`. Cast applied — upper bits are unused in practice.

5. **Sleep duration**: Computed as `now - last_quiescent_at` in `runnable`. Guard for `last_quiescent_at == 0` (first wakeup without a prior quiescent) emits zero.

## Observations

- `intf.h` already had `evt_runnable` and `evt_quiescent` structs pre-defined (sizes 40 and 32 bytes). No format changes needed.
- `task_ctx` already had `waker_pid`, `waker_tgid`, `waker_flags`, `waker_wake_flags` fields. These were zeroed placeholders waiting for `select_cpu`.
- `reader.py` KNOWN_SIZES already included 40 and 32. No section boundary detection changes needed.
- Pre-existing: `runq_wait_ns` shows large values at scheduler attach time due to stale `p->scx.runnable_at`.
- Pre-existing: `cargo fmt --check` shows diffs in `main.rs` and `output.rs` (not from this task).

## Task: cgroup filtering (2026-04-17)

### Deviation from task.md
task.md specifies `BPF_MAP_TYPE_CGROUP_ARRAY` + `bpf_task_under_cgroup(p, target)`.
These do not compose — kernel `cgroup_fd_array_lookup_elem` returns NULL; CGROUP_ARRAY is only usable via `bpf_current_task_under_cgroup` (filters `current`, violates task.md) or `bpf_skb_under_cgroup` (networking).

**Alternative used:** pass cgroup inode (`stat.st_ino`) as `const volatile u64 target_cgid`; BPF resolves per-callback via `bpf_cgroup_from_id` + `bpf_task_under_cgroup(p, cg)` + `bpf_cgroup_release(cg)`. Ancestor walk semantics preserved; still filters on `p`.

### Relevant references
- `scheds/include/scx/common.bpf.h:391-392` — `bpf_cgroup_release`, `bpf_cgroup_from_id` kfunc decls.
- `scheds/include/lib/cleanup.bpf.h:103` — `DEFINE_FREE(cgroup, ...)` (not used; we keep release explicit for clarity on the short gated path).
- cgroupv2 procs semantics: writing "0" to `<cgroup>/cgroup.procs` moves the calling task into that cgroup. Used from child `pre_exec` to avoid parent entering the cgroup.
- Cgroup inode == cgroup id. Verified via `stat /sys/fs/cgroup` == `/proc/self/cgroup` id for any test cgroup.

### Scope and safety
- No scheduling policy changes. Filtering drops events before `bpf_ringbuf_reserve` — no perturbation beyond the gate itself.
- No trace format change. `intf.h`, `output.rs`, `analysis/reader.py` untouched.

## Task: cgroup filtering — userspace half (2026-04-20)

Implemented the userspace half of Task 3 on top of the BPF gate that already
landed on 2026-04-17. BPF code was not modified.

### Scope reduction (mid-task)
First pass implemented three modes (spawn / attach / system-wide). The
operator then trimmed scope: **attach mode is dropped**, only spawn +
system-wide remain. All `attach`-related surface was removed in the same
session before handoff: `Cgroup::attach`, the `owned: bool` field on
`Cgroup`, the `cgroup.controllers` sniff, the `--cgroup` clap flag, the
`Mode::Attach` variant, and the mutex check between `--cgroup` and trailing
`-- cmd`. The BPF gate already supports attach (it just looks up by inode
id), so reintroducing it later is a thin userspace addition without
touching BPF or the on-disk format.

### Final shape
- `src/cgroup.rs` (new, ~100 LOC): `ensure_cgroup_v2_unified`, `Cgroup` with
  `create_temporary` / `procs_path` / `cgid`, unconditional `Drop`-time
  `rmdir`. No `attach`, no `add_pid`, no `path`, no `owned` flag — all of
  those were dead weight without a caller.
- `src/main.rs` (modified): `record` subcommand with two modes (spawn,
  system-wide), top-level `-o` legacy form preserved for backward
  compatibility, rodata wiring in `Scheduler::init`, `spawn_workload` with
  child-side `pre_exec` writing `b"0\n"` to `cgroup.procs`, and a
  `spawn_child_watcher` thread that flips the existing shutdown
  `AtomicBool` when the workload exits.

### Design decisions
1. **Cgroupv2 detection via `statfs(2)` `f_type == CGROUP2_SUPER_MAGIC`**
   instead of parsing `/proc/mounts`. Canonical kernel-side signal, no
   parsing edge cases. Hybrid mounts where v2 is at `/sys/fs/cgroup/unified`
   are rejected — the BPF gate uses `bpf_cgroup_from_id(target_cgid)` which
   only works in the unified hierarchy.
2. **Child writes its own pid via `pre_exec`**, not parent-side. Parent-side
   write would migrate `scx_invariant` itself into the target cgroup,
   recording our own scheduling. Async-signal-safe `pre_exec` uses raw
   `libc::open` / `libc::write` / `libc::close` and a `CString` allocated in
   the parent before fork.
3. **CLI: top-level `-o` and subcommand `-o` are independent fields**
   (no `clap` `global = true`), so `scx_invariant -o foo` keeps the
   pre-task-3 system-wide UX while `scx_invariant record [...]` exposes the
   spawn mode.
4. **Spawn exit code is always 0 on a successful trace** (per operator
   directive). The watcher logs the workload's exit status for visibility
   but does not propagate it.
5. **`last = true` not `trailing_var_arg = true`** for the `command` field.
   Clap panics if both are set; `last = true` already accepts
   hyphen-prefixed tokens (`-- stress-ng --cpu 4`) which is what the task
   asks for.
6. **Watcher is detached, not joined**, so a SIGINT that fires before the
   workload exits doesn't deadlock main on `child.wait()`. The thread is
   reaped by the kernel when the process exits. Cgroup `Drop` rmdir is
   best-effort and will warn (not panic) if the child is still alive.

### Pre-existing fmt diffs (not addressed in this task)
`main.rs:31` (clap struct attr), `main.rs:138` (`scx_ops_open!` macro),
`output.rs:71` — same diffs noted in 2026-04-16 entry, line 33.

### Open follow-ups for future phases
- Attach mode (`record --cgroup <path>` against existing cgroups, e.g.
  systemd slices). BPF side is already capable; reintroduce only if a real
  use case shows up.
- Hybrid-mount fallback (v2 at `/sys/fs/cgroup/unified`) is intentionally
  refused. If a user ever needs it, surface a `--cgroup-root` flag rather
  than auto-discovery.

## Task: PMU integration (Task 5, 2026-04-20)

### Final shape
- `src/pmu.rs` (new, ~170 LOC): `Pmu { fds: Vec<Vec<Option<OwnedFd>>> }`
  with `Pmu::open(nr_cpus)` and `Pmu::install(&BpfSkel)`. Single
  convenience entry `pmu::open_and_install(skel, nr_cpus)` keeps the
  call site in `Scheduler::init` to one line. `OwnedFd` handles
  close-on-drop so we don't need an explicit `Drop` impl on `Pmu`.
- `src/bpf/main.bpf.c`: four `BPF_MAP_TYPE_PERF_EVENT_ARRAY` maps
  (`pmu_instructions`, `pmu_cycles`, `pmu_l2_misses`,
  `pmu_stall_backend`) at `max_entries = SCX_INVARIANT_MAX_CPUS = 1024`
  (generous static upper bound — host has 144 CPUs); inline
  `read_pmc(map, cpu)` helper that swallows `bpf_perf_event_read_value`
  errors and returns 0; `invariant_running` snapshots the four counters
  into `tctx->pmc_*_start` slots that already existed (intf-side change
  done in an earlier pass) and stores `(u16)scx_bpf_cpuperf_cur(cpu)` in
  `evt->cpu_perf`; `invariant_stopping` writes `end - start` deltas.
- `src/main.rs`: `mod pmu;`, `Scheduler` gains `_pmu: Option<pmu::Pmu>`,
  `Scheduler::init` takes a new `nr_cpus: u16` arg and runs
  `pmu::open_and_install(&skel, nr_cpus)` between `scx_ops_load!` and
  `scx_ops_attach!`. Single call-site update at `main()`.

### Deviation from `work/task.md`
task.md §"Userspace mechanics" says `Pmu::install` is called "between
`scx_ops_open!` and `scx_ops_load!`". That ordering does not work with
libbpf: `bpf_map_update_elem` requires a valid map fd, and the perf-
event-array fd only exists after `bpf_object__load()` (i.e. after
`scx_ops_load!`). I install **after load and before attach**, which
matches what `scx_layered::create_perf_fds` and
`scx_cosmos::setup_perf_events` both do for their `scx_pmu_map`. The
result is identical from BPF's perspective — the maps are populated
before the very first running/stopping callback can fire.

### `cpu_perf` width verification
Kernel returns `u32` from `scx_bpf_cpuperf_cur` in range
`[1, SCX_CPUPERF_ONE]` (`kernel/sched/ext.c:9076`,
`kernel/sched/ext_internal.h:20`). `SCX_CPUPERF_ONE ==
SCHED_CAPACITY_SCALE == 1L << SCHED_FIXEDPOINT_SHIFT == 1024`
(`include/linux/sched.h:453,458`). Full range fits in u16; the cast in
`invariant_running` (`evt->cpu_perf = (u16)scx_bpf_cpuperf_cur(cpu)`)
is value-preserving on every supported config. trace-format slot stays
u16 per `intf.h`.

### Event encoding choices (aarch64 Neoverse V2)
- `pmc_instructions` = `PERF_TYPE_HARDWARE` /
  `PERF_COUNT_HW_INSTRUCTIONS`. Universal; no raw encoding needed.
- `pmc_cycles` = `PERF_TYPE_HARDWARE` / `PERF_COUNT_HW_CPU_CYCLES`.
  Universal.
- `pmc_l2_misses` = `PERF_TYPE_RAW` / `0x0017`
  (`ARMV8_PMUV3_PERFCTR_L2D_CACHE_REFILL` from
  `include/linux/perf/arm_pmuv3.h`).
- `pmc_stall_backend` = `PERF_TYPE_RAW` / `0x0024`
  (`ARMV8_PMUV3_PERFCTR_STALL_BACKEND` from same header). Note:
  `arm_pmuv3.c` also maps `PERF_COUNT_HW_STALLED_CYCLES_BACKEND` to
  `STALL_BACKEND` on this arch, but using the raw event keeps
  `pmu.rs` arch-explicit and matches what the trace metadata implies.
Host `armv8_pmuv3_0` PMU exposes both — verified via
`/sys/bus/event_source/devices/`.

### Verified PMU host availability (Neoverse V2, kernel 7.0.0+ test box)
`/proc/sys/kernel/perf_event_paranoid = 2`, so opening hardware events
requires root or `CAP_PERFMON`. The recorder is invoked under sudo per
PLAN.md §12 examples, so this is the expected path. Fall-through
behavior (paranoid=3, no CAP_PERFMON) was specifically engineered
into `Pmu::open`: per-CPU `EACCES` is logged once at warn level, the
slot stays unset, BPF reads return 0, the trace records 0 — matching
the pre-Task-5 placeholder. Recorder still starts.

### `bpf_perf_event_read_value` semantics on this kernel
Kernel signature is `(struct bpf_map *map, u64 flags, struct
bpf_perf_event_value *buf, u32 size)` — `flags` is the cpu index when
calling against a `BPF_MAP_TYPE_PERF_EVENT_ARRAY`. We pass `cpu`
directly (verified against `kernel/trace/bpf_trace.c:582-597` and
`tools/perf/util/bpf_skel/bperf_leader.bpf.c:44`). `enabled` and
`running` are read but currently ignored — see `read_pmc()` comment.

### Rejected during implementation
- **Process-attached perf events (`pid = task_pid`)**: would require a
  per-task `perf_event_open` and lifecycle plumbing through
  `task_ctx`. Doesn't compose with our cgroup-membership filter and
  scales poorly. Sticking with system-wide CPU-pinned per task.md
  Approach A.
- **Refusing to start when PMU unavailable**: explicitly rejected by
  task.md "Approach D".
- **Scaling for multiplexing**: 4 counters per CPU should fit on every
  PMU we care about. If measurement later shows divergence, the BPF
  side already calls `bpf_perf_event_read_value` (not the older
  `bpf_perf_event_read`), so `enabled`/`running` are already in `v`
  and we can scale without touching the on-disk format.

### Pre-existing fmt diffs (not addressed in this task)
Now five — `cgroup.rs:83`, `cgroup.rs:133`, `main.rs:32`, `main.rs:189`
(this was `main.rs:138` before this task; line shifted because
`Scheduler::init` grew a `nr_cpus` arg and a few lines of comments),
`output.rs:71`. None introduced by Task 5; verified via `cargo fmt
--check` on stash-vs-tree. The two `cgroup.rs` ones were not
documented in the 2026-04-20 cgroup entry but appear pre-existing —
flagging here so a future cleanup pass knows.

### Validation
- `cargo check -p scx_invariant` — success, only the pre-existing
  `event_count` warning.
- `cargo build --profile ci --locked -p scx_invariant` — success
  (BPF compiled and linked, including the four new perf-event-array
  maps and `read_pmc`).
- `cargo fmt -p scx_invariant -- --check` — only the five pre-existing
  diffs noted above; no new diffs introduced.
- Runtime gates 3–7 (smoke under sudo, IPC sanity, PMU-unavailable
  degradation, cgroup-scope regression, system-wide regression) require
  a sched_ext-capable kernel + sudo and were not run from the sandbox.
  Owed by the operator before merge.

### Open follow-ups
- x86 / non-aarch64 event encodings — out of scope per task.md.
  When added, keep `COUNTERS` table arch-gated rather than picking at
  runtime.
- Multiplexing scaling: add only after measurement shows divergence.
- EVT_TICK (Task 7) is the next pending item.

### Reviewer follow-up (2026-04-20, post-handoff): saturating PMC delta

Reviewer flagged H1: u64 underflow in `evt->pmc_*` when `read_pmc()`
returns 0 at stopping() while `tctx->pmc_*_start` is non-zero. Two
failure modes:

1. **Counter readable at start, unreadable at stop.** Transient
   `bpf_perf_event_read_value` failure (`-EBUSY` from event
   multiplexing pause, `-EOPNOTSUPP` during ARM PMU power state, any
   kfunc-returns-negative path) lands `end = 0`, `start > 0`. Naive
   `end - start` wraps to ~1.84e19, which would dominate any
   downstream sum/avg over the trace.

2. **`running` skipped, `stopping` fires.** Kernel pairs them via
   `SCX_TASK_QUEUED` (kernel/sched/ext.c:2864, 2954), but fork-into-
   SCX races, hotplug, and the bug in `85a2437aca3f` can desync them.
   `tctx->pmc_*_start` then carries a value from a previous quantum
   (typically smaller than current `end`), so this case usually
   produces an inflated-but-positive delta rather than underflow.

I had documented the **opposite** asymmetry (unset at start,
available at end → one-off oversized delta bounded by lifetime
counter size — acceptable) but missed the catastrophic direction.

Fix: introduced `static __always_inline u64 sat_sub(u64 end, u64
start)` next to `read_pmc()`; `invariant_stopping` calls `sat_sub`
for all four `pmc_*` writes. Returns 0 when `end < start`, matching
the start-side "no PMU data this quantum" semantics. No format
change, no behavior change in the happy path.

Case (2) is only partly addressed — sat_sub kills the underflow but
not the stale-`tctx` inflation. Proper fix is a per-quantum
generation bit on `task_ctx` (set in running, checked in stopping).
Deferred until measurement shows it happens; the stale path also
inflates `runtime_ns` (same root cause, pre-existing) and is better
fixed in one pass.

Optional follow-up: add a percpu counter for sat-sub triggers so we
can detect rate of underflow attempts in production. Skipped here to
keep the diff to the actual bug.

### Reviewer follow-up (2026-04-20, M1): unify pmc_* semantics

Reviewer flagged M1: same field name carrying different physical
units across event types in a shared on-disk format.
- `evt_running.pmc_*` carried raw start-of-quantum CPU lifetime
  snapshots.
- `evt_stopping.pmc_*` carried per-quantum deltas.

A future analyzer that iterates all events and sums `pmc_*` would
silently double-count (lifetime totals + per-quantum deltas) with no
way to detect the error from the trace alone. My original
justification ("downstream tools that only look at running events
still see meaningful counter values") was wrong: a single CPU-wide
lifetime counter snapshot from one arbitrary moment carries no
standalone signal — it only becomes meaningful when diffed against
another snapshot on the same CPU, which is exactly what the matching
evt_stopping delta already provides. So the start snapshots in
evt_running were both redundant *and* a footgun.

Fix (reviewer's preferred option 1):
- `invariant_running` still snapshots the four PMU counters into
  `tctx->pmc_*_start` (those are needed by stopping for the delta
  computation), but writes **zeros** into `evt->pmc_*` instead of
  the raw values.
- `evt->cpu_perf` stays populated — it IS standalone meaningful (a
  normalized [1, SCX_CPUPERF_ONE] frequency-state hint, not a
  counter).
- `intf.h` now documents the four `pmc_*` slots in `evt_running` as
  RESERVED-ZERO with rationale, so a future maintainer doesn't
  reintroduce the bug. `cpu_perf` got a one-liner explaining its
  range.
- `reader.py` "Sample PMU Events" block updated: the previous logic
  picked the first 3 RUNNING events with non-zero `pmc_cycles`,
  which would never trigger after this change. Now it picks the
  first 3 RUNNING events with non-zero `cpu_perf` and prints only
  `cpu_perf` for those (no `pmc_*`). STOPPING samples and the
  aggregate tables are unchanged — they were already correctly
  sourced from STOPPING only.

No on-disk format change. Older traces remain readable; their
non-zero `evt_running.pmc_*` values will simply be ignored by the
updated reader, which is the new contract.

Compatibility note: any third-party reader that was opportunistically
diffing evt_running.pmc_* values across pairs of events on the same
CPU loses that capability. Such a reader was already on shaky
ground (cross-task and cross-time interleaving makes the diff
attribute work to the wrong task) — strictly an improvement.

### Reviewer follow-up (2026-04-20, M2): drop dead-branch `Option<Pmu>`

Reviewer flagged M2: type signature said "PMU init might be absent"
(`Scheduler._pmu: Option<pmu::Pmu>`), runtime semantics said "hard-fail
on init" (`open_and_install(...).context(...)?`). The two
contradicted each other; the assignment was always `Some(pmu)`
because `?` consumed the `Err` branch. Per `work/task.md` Approach D
("recorder must always start, even with PMU disabled"), the type's
intent is the correct one — runtime had to be brought into
agreement.

Audit of failure paths in pmu.rs:
- `Pmu::open` already had **zero** Err-returning paths in its body —
  per-(counter, cpu) `perf_event_open` failures were already
  swallowed and stored as `None` slots, with one info/warn log per
  counter. The `Result<Self>` return was already dead-branch.
- `Pmu::install` had one Err path: `bpf_map_update_elem` failure.
  Per-call failure modes are `ENOMEM` (transient kernel pressure),
  `EINVAL` (programming error — wrong map size/type, would be
  caught in dev), and `E2BIG` (cpu >= max_entries=1024, can't
  happen on the 144-CPU target). All three match the "be useful,
  not absent" stance — demoting them to a per-counter warn log
  with the slot left unset (BPF reads return 0) is the right
  behavior.

Fix:
- `Pmu::open(nr_cpus) -> Self` (was `Result<Self>`). No body change
  beyond the return-type narrowing.
- `Pmu::install(&self, &BpfSkel)` (was `Result<()>`). Per-(counter,
  cpu) failures are tallied; one `warn!` per counter at the end if
  `failed > 0`, including the first error string and the ok/failed
  count. No spam when a systemic failure hits every CPU.
- `pmu::open_and_install(skel, nr_cpus) -> Pmu` (was `Result<Pmu>`).
  Direct sequence of two infallible calls.
- `Scheduler._pmu: pmu::Pmu` (was `Option<pmu::Pmu>`); doc-comment
  rewritten to explain the new semantics.
- `Scheduler::init` call site reduced to `let pmu =
  pmu::open_and_install(&skel, nr_cpus);` — no `?`, no `.context`.
- Dropped `anyhow::{Context, Result}` import from pmu.rs (no
  longer used there). `main.rs` still uses `Context` elsewhere
  (cgroup, topology, ctrlc), import retained.

The whole change is one of contracts and types; no observable
behavior change in the happy path. In the unhappy path
(`bpf_map_update_elem` fails on some CPUs), the recorder used to
abort and now logs + continues with those slots reading zero — the
behavior `task.md` actually asked for.

Also revisited the stack-allocated `info!("PMU events installed for
{} CPUs", nr_cpus)` log line in `Scheduler::init`. After the M2 fix
the message can be misleading (some CPUs may not have been
installed). Left as-is for now since `Pmu::install`'s own per-counter
warn already surfaces partial failures; if it becomes a source of
confusion, change to "PMU init complete; see prior warns for
partial-failure detail" as a single-line tweak.
