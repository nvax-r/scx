# SCX Overview for Agents

This repository contains `sched_ext` schedulers, shared Rust crates, and tooling around BPF scheduling on Linux.

This guide is written for coding agents and human collaborators. It provides enough project context to work safely while keeping scheduler-specific implementation depth focused on `scx_invariant`.

## Repository map

- `scheds/`: scheduler implementations and shared scheduler-side includes.
- `scheds/rust/`: Rust userspace scheduler binaries, including `scx_invariant`.
- `rust/`: shared Rust crates used across schedulers (`scx_utils`, `scx_cargo`, etc.).
- `tools/`: supporting tools (for example `scxtop`) that are not scheduler policy implementations.
- `services/`: systemd and service integration.
- `.github/workflows/ci.yml`: CI behavior for formatting, checking, verifier stats, and tests.

## What `scx_invariant` is

`scx_invariant` is a workload profiling tool implemented as a minimal passthrough `sched_ext` scheduler. Its job is to record scheduler-invariant workload identity signals into a binary `SCXI` trace.

Primary implementation path:

- `scheds/rust/scx_invariant/src/main.rs`
- `scheds/rust/scx_invariant/src/recorder.rs`
- `scheds/rust/scx_invariant/src/output.rs`
- `scheds/rust/scx_invariant/src/bpf/intf.h`
- `scheds/rust/scx_invariant/analysis/reader.py`

## Scope rule

Agents should understand the whole SCX framework to make good decisions, but scheduler-specific edits should target `scx_invariant` only unless the task explicitly says otherwise.

For `scx_invariant`, preserve scheduling behavior by default. Do not change scheduling policy or dispatch logic unless the task explicitly requires it and includes rationale.

## Workflow entrypoints

Use these files in order:

1. `docs/overview.md` (this file)
2. `docs/architecture.md`
3. `docs/conventions.md`
4. `docs/eval.md`
5. `docs/glossary.md`
6. `agents/program.md` or `agents/reviewer.md`
7. `work/task.md` (human-authored task source of truth)

