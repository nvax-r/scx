# Task: spawn-mode cgroup filtering for scx_invariant (userspace half)

> **Scope reduction (2026-04-20):** attach mode (`--cgroup <path>`) was cut
> for this iteration. Spawn mode covers the only use case anyone is asking
> for today. Attach can come back later as a separate task without affecting
> on-disk format or BPF.

## Status going in

The BPF half is already in tree (see `work/notes.md` 2026-04-17 entry and
`scheds/rust/scx_invariant/src/bpf/main.bpf.c:25-42`):

- `const volatile bool cgroup_filtering` and `const volatile u64 target_cgid`
  rodata are declared.
- `is_target_task(p)` resolves the target cgroup with `bpf_cgroup_from_id` +
  `bpf_task_under_cgroup(p, cg)` and is gated at the top of every recording
  callback (`running`, `stopping`, `runnable`, `quiescent`, `select_cpu`).
- `enqueue` is intentionally **not** gated, so dispatch behavior is preserved.
- Trace format is unchanged; filtering happens before `bpf_ringbuf_reserve`.

This task delivers the **Rust userspace** that drives that BPF: cgroup
lifecycle management, CLI surface, rodata config wiring, and workload-exit
shutdown.

## Goal

Scope `scx_invariant` recording to a single workload (and all of its
descendants) instead of recording every task on the system. Filtering must be
correct under `fork()`, `clone(CLONE_THREAD)`, and arbitrary cgroup nesting.

## Approach

Approach **A — rodata cgroup-id + userspace cgroup manager** (chosen in
`work/plan.md`):

- Userspace creates or attaches a cgroupv2 directory, derives its inode as the
  cgroup id, and writes `cgroup_filtering = true` and `target_cgid = <inode>`
  into BPF rodata before `load`.
- BPF keeps the `is_target_task(p)` gate already in `main.bpf.c`.
- Cgroup membership is the source of truth — kernel sets it inside
  `copy_process()` before the new task is schedulable, so fork and thread
  creation inherit membership for free. We maintain no PID set of our own.
- We filter on `p` (the wakee in wakeup callbacks), never `current` (the
  waker). This is already enforced in BPF; CLI and docs must not regress it.

Rejected alternatives (recorded in `work/plan.md`):

- **B. `BPF_MAP_TYPE_CGROUP_ARRAY` + `bpf_current_task_under_cgroup`** —
  filters on `current`, breaks `runnable` / `select_cpu` semantics where `p`
  is the wakee.
- **C. PID-tree tracking via `sched_process_fork` / userspace map** —
  higher complexity, race-prone, and out of scope vs. cgroup inheritance.

## Operating modes (CLI)

Add a `record` subcommand to `scx_invariant`. Two modes:

1. **Spawn** — `scx_invariant record -o trace.scxi -- <cmd> [args...]`
   - Create a fresh cgroup at `/sys/fs/cgroup/scx_invariant-<our-pid>`.
   - `fork+exec` the workload into it (see "Spawn mechanics" below).
   - Record until the workload exits, then `rmdir` the cgroup.
2. **System-wide** — `scx_invariant record -o trace.scxi` (no trailing
   command), or the legacy top-level form `scx_invariant -o trace.scxi`.
   - Set `cgroup_filtering = false`. Behavior is identical to today's recorder.
   - Kept for debugging/regression testing.

CLI parsing notes:

- Use clap subcommand structure; trailing command args via `last = true`
  (clap rejects combining it with `trailing_var_arg`).
- `--cgroup` is intentionally not implemented in this iteration; clap will
  reject it as an unknown flag.

## Spawn mechanics

`scx_invariant` itself must NOT enter the target cgroup, otherwise it would
record its own scheduling activity.

- Use `std::process::Command::pre_exec()` so the **child** writes its own PID
  (or "0", which the kernel resolves to the calling task) into
  `<cgroup>/cgroup.procs` after `fork()` and before `exec()`. The parent
  stays in its original cgroup.
- There is a brief window (a few microseconds) where the child is still in
  the parent cgroup before it writes itself in. The handful of stray events
  this produces is acceptable — do not try to engineer it away.

## Cgroup lifecycle

- Use the path `/sys/fs/cgroup/scx_invariant-<our-pid>` so collisions from a
  crashed prior run can't happen.
- On startup, if an empty leftover cgroup exists at our chosen path, `rmdir`
  it and create a new one.
- On shutdown, `rmdir` best-effort from a `Drop` impl on the owned-cgroup
  variant. Log failures, never panic.
- Attach-mode `Cgroup` must NOT `rmdir` on drop.

## Shutdown behavior

- Keep the existing SIGINT `AtomicBool` shutdown.
- In spawn mode, add a child-exit watcher (thread or async task) that flips
  the same shutdown flag when the spawned workload exits. The recorder loop
  already polls `shutdown` (`src/recorder.rs:58`); no recorder changes are
  required.
- Attach mode and system-wide mode shut down on SIGINT only.

## Error behavior

- If the system is cgroupv1-only, or hybrid without unified v2 mounted at
  `/sys/fs/cgroup`, refuse to start with a clear error. Do **not** silently
  fall back to system-wide.
- In spawn mode, if cgroup creation, `cgroup.procs` write, or the child
  process spawn fails, exit non-zero with a clear error and `rmdir` any
  cgroup we created.

## Files in scope

- **New**: `scheds/rust/scx_invariant/src/cgroup.rs` (~80 LOC)
  - `pub fn ensure_cgroup_v2_unified() -> Result<()>` — guard, fail fast on
    non-v2 or wrong mount.
  - `pub struct Cgroup { path: PathBuf }` with:
    - `Cgroup::create_temporary(name: &str) -> Result<Self>`
    - `Cgroup::procs_path(&self) -> PathBuf` (used by `pre_exec`)
    - `Cgroup::cgid(&self) -> Result<u64>` (inode of cgroup dir, fed to rodata)
    - `Drop` impl: best-effort `rmdir`.
- **Modified**: `scheds/rust/scx_invariant/src/main.rs` (~80 LOC)
  - Restructure `Args` into a clap subcommand tree with `record { -o, trailing cmd }`.
  - Build the appropriate `Cgroup` (or `None` for system-wide).
  - Wire `open_skel.maps.rodata_data.as_mut().unwrap().cgroup_filtering` and
    `target_cgid` between `scx_ops_open!` and `scx_ops_load!` in
    `Scheduler::init`.
  - In spawn mode, spawn the workload via `Command::pre_exec()` and start
    the child-exit watcher that flips the shutdown flag.
- **Unchanged in this task**:
  - `src/bpf/main.bpf.c` — already gated; do not modify unless a bug surfaces.
  - `src/bpf/intf.h`, `src/output.rs`, `analysis/reader.py` — trace format
    is not changing.
  - `src/recorder.rs` — already supports the external shutdown flag.

If any file outside `scheds/rust/scx_invariant/` would need to change, stop
and document the rationale in `work/notes.md` per `docs/conventions.md`.

## Trace format impact

None. Event layouts are unchanged; filtering happens before the ring buffer.

## Scheduling-behavior invariants

These must hold after the change (consistent with the profiling-first rule
in `docs/conventions.md` and `PLAN.md` §13):

- `enqueue` remains the single-line passthrough into `SCX_DSQ_GLOBAL`. No
  cgroup gate on dispatch.
- `select_cpu` continues to return `prev_cpu` for in-scope tasks and to
  return `prev_cpu` for out-of-scope tasks (it just skips waker attribution).
- No new BPF maps, no new BPF callbacks, no policy logic.

## Out of scope

- **Attach mode** (`--cgroup <path>` against a pre-existing cgroup such as
  a systemd slice). Cut from this iteration; revisit as a separate task if
  a real use case shows up. Removing it cuts `Cgroup::attach`, the
  `owned: bool` flag, the `cgroup.controllers` sniff, and the
  CLI mutex check — all of which were dead weight without a caller.
- No PID hash map, no `sched_process_fork` / `sched_process_exit` hooks.
  Cgroup inheritance is the correct mechanism.
- No filtering on `current` — semantics break in wakeup callbacks.
- No controller attachment. An empty cgroup with no `cpu`/`memory`/etc.
  controllers enabled is sufficient for membership-only tracking.
- No BPF changes (the gating, rodata, and helpers are already in place).
- No trace-format changes (`intf.h` / `output.rs` / `reader.py` untouched).

## Validation gates

Per `work/plan.md` and `docs/eval.md`:

1. **Build**: `cargo check -p scx_invariant`, then
   `cargo build --profile ci --locked -p scx_invariant`.
2. **Format**: `cargo fmt --check` (only verify no new diffs are introduced;
   pre-existing diffs in `main.rs` / `output.rs` documented in `notes.md`
   are not regressions to address here).
3. **Spawn mode**:
   `sudo target/ci/scx_invariant record -o /tmp/spawn.scxi -- stress-ng --cpu 4 --timeout 5`
   - Process table from `analysis/reader.py /tmp/spawn.scxi` should contain
     only the `stress-ng` PID tree (parent + workers); the trailing event
     count must be non-zero.
4. **Negative test**: while step 3 is recording, run an unrelated
   `stress-ng --cpu 2 --timeout 5` outside the target cgroup; verify those
   PIDs are absent from `/tmp/spawn.scxi`.
5. **System-wide regression**:
   `sudo target/ci/scx_invariant record -o /tmp/system.scxi` (no command)
   and the legacy `sudo target/ci/scx_invariant -o /tmp/system_legacy.scxi`
   — behavior must match today's recorder semantics (`SCXI` magic,
   topology, non-zero events, populated process table).
6. **cgroupv1-only host** (where available, otherwise document as untested):
   the scheduler must refuse to start with a clear error message.

## Documentation updates

- `scheds/rust/scx_invariant/PLAN.md` — flip Task 3 from "Pending" to "Done"
  in the roadmap table; note that BPF and userspace are now both complete.
- `work/notes.md` — append final design decisions, edge cases hit during
  spawn-mode bring-up, and any deviations from this task spec.
- `work/changelog.md` — concise entry describing the userspace cgroup
  manager, CLI surface, rodata wiring, and validation evidence.
