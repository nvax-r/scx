  # Task: Minimal `ops.tick()` plumbing for `scx_invariant` (Task 7)

  > **Premise:** Task 5 already landed. `scx_invariant` already gets the PMU truth it needs from `running` /
  `stopping`, and that is the current source of record. In upstream `sched_ext`, `ops.tick()` is a periodic callback
  on a currently running SCX task; it is not a precise per-quantum boundary. This task is intentionally a hook-only
  change. Do not turn it into a second PMU path.

  ## Status going in

  - `scheds/rust/scx_invariant/src/bpf/main.bpf.c` already implements the real recording callbacks:
    `select_cpu`, `enqueue`, `running`, `stopping`, `runnable`, `quiescent`.
  - PMU accounting already exists and is intentionally tied to `running` / `stopping`.
  - Cgroup scoping already exists via `is_target_task(p)`.
  - The current trace format and reader are correct as-is for the current branch state.
  - The old Task 7 wording in `scheds/rust/scx_invariant/PLAN.md` is now wrong for this branch and must be updated.

  ## Goal

  Add a minimal `ops.tick()` callback to the BPF scheduler and nothing more.

  Success means:

  - the BPF scheduler exposes a valid `.tick` callback,
  - the scheduler still behaves exactly as before,
  - PMU semantics stay exactly as they are today,
  - the trace format stays exactly as it is today,
  - no new userspace or reader work is introduced.

  ## Kernel semantics to respect

  - `tick()` is periodic while an SCX task is running.
  - `tick()` is not a precise scheduling-quantum boundary.
  - `tick()` is not a replacement for `running` / `stopping`.
  - This task is plumbing only, not a new recording feature.

  ## MUST do

  1. In `scheds/rust/scx_invariant/src/bpf/main.bpf.c`, add a new callback named `invariant_tick` using the same
  declaration style as the existing SCX callbacks.

  2. The callback must be intentionally minimal:
     - check `is_target_task(p)` first,
     - return immediately for out-of-scope tasks,
     - do nothing else for in-scope tasks and return.

  3. Wire the callback into `SCX_OPS_DEFINE(invariant_ops, ...)` by adding:
     - `.tick = (void *)invariant_tick,`

  4. Add a short comment directly above the callback explaining the intent:
     - this is a reserved future hook,
     - it is intentionally a no-op,
     - PMU and trace semantics must not be added here without a separate task/spec.

  5. Update `scheds/rust/scx_invariant/PLAN.md` so Task 7 is no longer described as periodic PMU snapshots for long-
  running quanta.
     Replace that wording with the new scope:
     - minimal `ops.tick()` hook,
     - reserved for future use,
     - no current trace or PMU semantics.

  6. Update `work/notes.md` with the rationale for the rescope:
     - Task 5 already provides the PMU path we need,
     - `tick()` overlaps semantically if used for the same purpose,
     - the branch is only reserving the kernel hook for now.

  7. Update `work/changelog.md` with a concise entry stating that Task 7 now adds only minimal `ops.tick()` plumbing
  and intentionally does not emit data.

  ## MUST NOT do

  - Do not read PMU counters in `tick()`.
  - Do not reserve or submit ringbuf events in `tick()`.
  - Do not add or emit any `tick` event in the trace stream.
  - Do not modify `scheds/rust/scx_invariant/src/bpf/intf.h`.
  - Do not modify `scheds/rust/scx_invariant/src/output.rs`.
  - Do not modify `scheds/rust/scx_invariant/analysis/reader.py`.
  - Do not modify `scheds/rust/scx_invariant/src/main.rs`.
  - Do not modify `scheds/rust/scx_invariant/src/pmu.rs`.
  - Do not add new BPF maps.
  - Do not add new task-local storage fields.
  - Do not add new rodata/config flags.
  - Do not change `enqueue`.
  - Do not change `select_cpu`.
  - Do not change `running` / `stopping` PMU behavior.
  - Do not change scheduler policy or dispatch behavior.
  - Do not “make the callback useful” by slipping in debug counters, temporary prints, placeholder payloads, or
  speculative future logic.

  If any of the above appears necessary to make the change compile or attach, stop and document why in `work/
  notes.md` before proceeding further.

  ## Files in scope

  - **Modify:** `scheds/rust/scx_invariant/src/bpf/main.bpf.c`
  - **Modify:** `scheds/rust/scx_invariant/PLAN.md`
  - **Modify:** `work/notes.md`
  - **Modify:** `work/changelog.md`

  ## Files expected to remain unchanged

  - `scheds/rust/scx_invariant/src/bpf/intf.h`
  - `scheds/rust/scx_invariant/src/output.rs`
  - `scheds/rust/scx_invariant/analysis/reader.py`
  - `scheds/rust/scx_invariant/src/main.rs`
  - `scheds/rust/scx_invariant/src/pmu.rs`
  - `scheds/rust/scx_invariant/src/recorder.rs`
  - `scheds/rust/scx_invariant/src/cgroup.rs`

  ## Scheduling-behavior invariants

  These must still be true after the change:

  - `enqueue` remains the passthrough insert into `SCX_DSQ_GLOBAL`.
  - `select_cpu` remains attribution-only and does not become a policy hook.
  - `running` / `stopping` remain the only PMU-producing path.
  - cgroup scoping remains an instrumentation boundary, not a dispatch boundary.
  - The trace contract stays stable.

  ## Validation gates

  1. `cargo fmt --check`
  2. `cargo check --profile ci --locked -p scx_invariant`
  3. `cargo build --profile ci --locked -p scx_invariant`
  4. Smoke-run the existing recorder path on a CPU-bound workload and confirm attach/run behavior is unchanged.
  5. Decode the resulting trace with the existing reader and confirm no reader changes were needed.
  6. Confirm the diff only contains the BPF file and the planned docs/worklog files listed above.

  ## Expected outcome

  After this task:

  - `scx_invariant` has a valid `ops.tick()` hook,
  - the hook is intentionally inert,
  - Task 5 remains the only PMU truth path,
  - the trace format is unchanged,
  - the reader is unchanged,
  - future Task 7 semantics can be designed separately instead of being guessed into the current branch.