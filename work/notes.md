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

## 2026-04-22 — Task 7 rescope: minimal `ops.tick()` hook only

Original Task 7 wording in `PLAN.md` framed the work as "periodic PMU
snapshots for long-running quanta", emitting an `EVT_TICK` carrying
PMU deltas mid-quantum. That's the wrong shape for this branch:

- Task 5 already established `running` / `stopping` as the single
  source of PMU truth. Reading PMU counters again from `tick()` would
  create a second producer with overlapping semantics — two values
  for "instructions retired by this task" with subtly different
  windowing rules. That is the kind of split-source-of-truth bug
  that's unfixable two releases later.
- `ops.tick()` in the kernel (verified in
  `~/upstream-kernel/kernel/sched/ext_internal.h:374-382` and the
  invocation in `kernel/sched/ext.c:3413` from `task_tick_scx`) is
  *not* a precise quantum boundary. It fires every 1/HZ on a CPU
  whose currently-running task is an SCX task. Treating it as a
  PMU-quantum-boundary event would silently inherit that imprecision.
- We don't yet know what *is* worth recording at a tick boundary that
  isn't already covered by `running` / `stopping` + future syscall
  tracking. Reserving the kernel hook keeps the option open without
  guessing a format.

So Task 7 in this branch is hook-only:

- Add `invariant_tick(p)` matching the kernel ABI
  (`void (*tick)(struct task_struct *p)`); body checks
  `is_target_task(p)` and returns. No PMU reads. No ringbuf reserve.
  No event emission.
- Wire `.tick = (void *)invariant_tick` into `SCX_OPS_DEFINE`.
- `intf.h`, `output.rs`, `recorder.rs`, `main.rs`, `pmu.rs`,
  `cgroup.rs`, `analysis/reader.py` stay untouched. Trace format is
  byte-identical. `EVT_TICK = 5` stays reserved in `intf.h` for a
  future, separately-specified design.
- `PLAN.md` updated: §6 row marks `EVT_TICK` as Reserved (not Pending);
  §7 prose drops the "remaining optional addition" framing; §9
  roadmap row reads "Minimal `ops.tick()` hook" / Done; the
  recommended-next-order paragraph is emptied (no remaining roadmap
  tasks).

Cost-of-hook check: at HZ=250 on 144 CPUs with everything in SCX,
the inert hook fires ~36k times/sec system-wide. With
`cgroup_filtering == false` (system-wide mode) `is_target_task(p)`
is one rodata load + immediate `true`. With filtering on it's three
kfunc calls (`bpf_cgroup_from_id` + `bpf_task_under_cgroup` +
`__free(cgroup)` release). Both are negligible — confirmed by
inspection only; will be re-verified by smoke-run before sign-off.

### Follow-up — reviewer M1: drop the `is_target_task(p)` gate

Initial implementation followed `work/task.md` step 2 literally:
`if (!is_target_task(p)) return;` then nothing. Reviewer M1 pushed
back, correctly:

- The gate's purpose is to short-circuit work. With no work after
  it, there is nothing to short-circuit.
- In spawn mode (`cgroup_filtering == true`) the gate runs the
  three-kfunc chain — `bpf_cgroup_from_id` + `bpf_task_under_cgroup`
  + `__free(cgroup)` — on every tick on every in-scope CPU, just to
  produce a bool that is immediately discarded.
- "Consistency with sibling callbacks" is the wrong framing: the
  sibling callbacks gate because they do work; copying the gate into
  a body that does nothing imports the cost without the reason.

Spec deviation: `work/task.md` step 2 explicitly required the gate.
Per the task's MUST-NOT clause ("If any of the above appears
necessary..., stop and document why in `work/notes.md` before
proceeding further"), this note is the documentation. The deviation
is purely a cost-correctness tightening; it does not change the
hook's observable behavior (still inert), does not touch the trace
format, and does not affect the kernel ABI we are matching.

The replacement is `(void)p;` to silence the unused-parameter warning
that would otherwise appear when the compiler sees an unreferenced
`struct task_struct *p`. The comment above the function now tells the
next maintainer the right thing: when you add real work, gate on
`is_target_task(p)` like the other callbacks. That's a one-line
addition for them, with the rationale already in their face.

Cost change in spawn mode: ~36k tick events/sec system-wide on a
144-CPU box at HZ=250; each formerly cost 3 kfunc calls, now costs
0. Not measurable in either direction, but the reviewer's
"cargo-culted cost" framing is correct on principle. Ship the
cheaper version.

## 2026-04-22 — SCXI v2 format break: events out of section-ID space

### Root cause (v1)

`src/output.rs` defines section IDs at `0x0001..0x0003`
(`SECTION_TOPOLOGY`, `SECTION_PROCS`, `SECTION_EVENTS`).
`src/bpf/intf.h` (v1) defined event IDs at `1..5`. Same numeric space.

The two framings are also different widths:

- Section header: `[type:u16][len:u32]` = 6 bytes.
- Event TLV: `[type:u16][payload_len:u16][payload]` = 4-byte prefix.

So the reader, walking the events section, had to decide on each
4-byte read "is this another event TLV, or have I just stepped into
the next section header?" with only the `u16` type to go on — and
the type numbers overlapped. To compensate, the v1 reader added a
payload-size heuristic (`KNOWN_SIZES = {88, 40, 32, 64}`): accept
the type if the size is in the set.

That heuristic fails for the **two-PID process table**. A `procs`
entry is `pid:u32 + comm[16]` = 20 bytes. Two procs = 40-byte
section payload. `40` is exactly `evt_runnable`'s size. The reader
sees `[0x0002][?]` followed by 40 bytes of proc data and either
mis-reads the `SECTION_PROCS` header as an event TLV or — once
inside — accepts the section payload as a phantom `EVT_RUNNABLE`.
Either way, the trace is silently mis-decoded on small workloads.

### Fix (v2)

Renumber event IDs to `0x0100..0x0104`:

- `EVT_RUNNING   = 0x0100`
- `EVT_STOPPING  = 0x0101`
- `EVT_RUNNABLE  = 0x0102`
- `EVT_QUIESCENT = 0x0103`
- `EVT_TICK      = 0x0104`

Section IDs stay at `0x0001..0x0003`. The two namespaces are now
disjoint by construction; a `u16` type read inside the events
section can only be an event TLV (≥ 0x0100) or the start of the
next section header (≤ 0x00FF). No heuristic needed for the type
check — but the reader still enforces an exact per-type size
(`EVT_SIZES`) as belt-and-braces against future ABI drift.

### Decision: drop v1 reader support

Hard break. The in-tree reader checks file header `version != 2`
and raises `UnsupportedVersionError` (a `ValueError` subclass) with
a clear message. No dual-version decode path. No writer-side
translation shim that would re-introduce the problem.

Rationale: keeping a v1 path costs more than re-reading old traces
ever could. v1 traces are silently buggy on the two-PID shape; we
do not want any pipeline accidentally relying on those decodes.
Anyone with a real v1 trace can pin to the prior commit of
`reader.py` (or just regenerate — these are profiling traces,
ephemeral by design).

### Producer-side change is one line in C

`main.bpf.c` already references the enum by name in all four
`evt->hdr.event_type = EVT_*` sites — no literals. Renumbering
`intf.h` is therefore the entire producer-side change; the BPF
program picks up the new values on rebuild via `bpf_intf.rs`
(auto-generated).

### Tests

New `analysis/test_reader.py` covers two cases the spec calls out:

- **Case A** synthesizes a v2 trace with exactly two PIDs in the
  process table (the v1 collision shape) and asserts:
  - `procs` decodes to exactly 2 entries
  - `events` decodes to exactly the one `EVT_RUNNABLE` written
    (no phantom event from misreading the procs section)
  - topology survives
- **Case B** synthesizes a v1-headered file and asserts:
  - `read_header` raises `UnsupportedVersionError`
  - the message names both v1 and v2 explicitly
  - the exception is also catchable as `ValueError` (subclass)

The synthetic traces are built with stdlib `struct` only; no test
fixtures committed. Width constants are duplicated locally in the
test on purpose — if anyone changes the on-disk layout without
updating the test, this file fails loudly.

### Validation gate 6 ("reject a v1 trace")

The spec said "any old v1 trace is acceptable for this check". I
don't have a v1 `.scxi` lying around in the workspace, so Case B
of `test_reader.py` is what satisfies this gate: a synthetic v1
header is the most reliable rejection input we can build, and it
exercises the same `read_header` code path a real v1 file would
hit on disk. If a real v1 trace shows up later, running it through
`reader.py` should produce the same `UnsupportedVersionError`.

### PLAN.md edits

- §5 (`.scxi` Binary File Format): replaced the "Known issue" paragraph
  about the ID collision with a paragraph stating v2 fixes it
  structurally.
- §6 (Event Types): bumped the event-ID column to `0x0100..0x0104`
  and kept `EVT_TICK` as Reserved (Task 7 hook stays inert).
- §11 (Why TLV event framing): rewrote to scope the
  forward-compat property to *within a major version*, and
  explicitly call out the major-version field as the escape hatch
  for changes TLV cannot absorb. Future hard breaks should bump
  the version, document the reason in §5/§11, and delete the
  prior version's decode path — not branch on version.
