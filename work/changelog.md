# Work Changelog

Chronological record of completed changes.

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
