# Work Changelog

Chronological record of completed changes.

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
