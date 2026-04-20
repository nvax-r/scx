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
