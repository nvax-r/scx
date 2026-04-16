# Evaluation Guide for `scx_invariant` Work

This file defines the default Definition of Done for `scx_invariant` tasks.

## Baseline checks

Run from repo root:

- `cargo fmt --check`
- `cargo check --profile ci --locked`

If the change could affect broader workspace behavior:

- `cargo nextest run --cargo-profile ci --workspace --locked --no-fail-fast --status-level fail --success-output never`

## `scx_invariant` targeted checks

Build only the target package:

- `cargo build --profile ci --locked -p scx_invariant`

For local runtime sanity (on sched_ext-capable kernel):

- `sudo target/ci/scx_invariant -o /tmp/sample.scxi` (or `target/release/scx_invariant` depending on profile)
- stop with Ctrl-C after a short capture
- `python3 scheds/rust/scx_invariant/analysis/reader.py /tmp/sample.scxi`

Expected minimum signals:

- file starts with `SCXI` magic (reader succeeds),
- topology is parsed,
- event counts are non-zero under workload,
- process table is present at finalize.

## Profiling-first acceptance criteria

Unless explicitly requested otherwise:

- no scheduler policy/dispatch behavior changes,
- changes are instrumentation, trace quality, robustness, or analysis improvements.

If policy logic changes are task-authorized, include:

- explicit rationale in notes/changelog,
- risk assessment,
- evidence that profiling objectives still hold.

## Format compatibility checklist

If event or section layout changes:

- update producer structs/constants in `src/bpf/intf.h`,
- update writer/parser assumptions in `src/output.rs`,
- update reader decode paths in `analysis/reader.py`,
- document compatibility note in `work/changelog.md`.

