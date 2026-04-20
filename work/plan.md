  1. Approach options (and recommendation)

  - A. rodata cgroup-id + userspace cgroup manager (Recommended)
    Keep current BPF is_target_task(p) model. Add userspace setup for cgroup lifecycle and pass cgroup_filtering/
    target_cgid through rodata.
    Best balance of correctness, minimal kernel perturbation, and smallest diff.
  - B. CGROUP_ARRAY + current-task helpers
    Wrong semantics for wakeup paths (current vs target p), so this does not meet scope.
  - C. PID-tree tracking in userspace/BPF maps
    Higher complexity, race-prone, and explicitly out-of-scope vs cgroup inheritance.

  2. Design for Cursor to implement (step-by-step)
  3. Add scheds/rust/scx_invariant/src/cgroup.rs:

  - Cgroup::create_temporary("scx_invariant-<pid>")
  - Cgroup::attach(path)
  - Cgroup::add_pid(pid) (write to cgroup.procs)
  - Cgroup::cgid() (inode as cgroup id)
  - Drop cleanup for owned temp cgroup (rmdir best-effort)
  - ensure_cgroup_v2_unified() guard (fail fast on non-v2 or wrong mount)

  2. Extend CLI in src/main.rs:

  - Add subcommand record
  - Modes:
      - record -o <file> -- <cmd ...> (spawn mode)
      - record -o <file> --cgroup <path> (attach mode)
      - record -o <file> (system-wide mode)
  - Parse trailing command args with clap trailing_var_arg/last.

  3. Wire BPF config before load in Scheduler::init:

  - Add config struct, e.g. { cgroup_filtering: bool, target_cgid: u64 }
  - Set open_skel.maps.rodata_data.as_mut().unwrap().cgroup_filtering
  - Set ...target_cgid
  - Then load + attach as today.

  4. Spawn-mode child placement:

  - Use Command + pre_exec so child writes itself to <cg>/cgroup.procs before exec.
  - Parent remains outside target cgroup.
  - Compute target cgid from created cgroup dir inode.

  5. Shutdown behavior:

  - Keep SIGINT AtomicBool.
  - Add child-exit watcher thread in spawn mode: when child exits, set shutdown flag.
  - Recorder loop already supports external shutdown; no format changes.

  6. Keep BPF scheduling behavior unchanged:

  - Do not gate enqueue.
  - Keep current event gating (running/stopping/runnable/quiescent/select_cpu) on target task p.

  7. Update docs:

  - scheds/rust/scx_invariant/PLAN.md task status
  - work/notes.md final decisions and edge-case notes.

  3. Validation gates Cursor should run
  4. cargo check -p scx_invariant
  5. Spawn mode:

  - sudo scx_invariant record -o /tmp/a.scxi -- stress-ng --cpu 4 --timeout 5
  - Reader should show only stress workload tree PIDs.

  3. Attach mode:

  - Record a known cgroup path; ensure only that cgroup’s tasks are in trace.

  4. Negative test:

  - Run unrelated workload outside target cgroup; verify its PIDs are absent.

  5. System-wide regression:

  - Run without --cgroup and without command; behavior matches current recorder semantics.