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
