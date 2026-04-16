# SCX Architecture and `scx_invariant`

## Repository directory structure

The agent should understand the whole repository layout before making scoped edits.

```text
scx/
├── scheds/        # Scheduler implementations and shared scheduler-side includes
├── rust/          # Shared Rust crates used by schedulers/tools
├── tools/         # Operational and analysis tooling (for example scxtop)
├── services/      # Service/system integration artifacts (for example systemd)
├── scripts/       # Utility scripts for tracing, diagnostics, and development
├── lib/           # Shared non-crate support assets/libraries used by repo components
├── .github/       # CI workflows and automation
├── .nix/          # Nix-based reproducible build/dev environment configuration
├── target/        # Build output (generated artifacts, not source of truth)
├── docs/          # Agent/human onboarding, architecture, conventions, and evaluation guides
├── agents/        # Agent role playbooks and task prompt templates
└── work/          # Active task coordination files (`task.md`, notes, changelog)
```

## What each top-level area does

- `scheds/`: Core scheduler code. For this workflow, scheduler-specific implementation should stay in `scheds/rust/scx_invariant` unless task scope explicitly expands.
- `rust/`: Reusable crates (`scx_utils`, `scx_cargo`, etc.) that provide loading/build/runtime helpers across schedulers.
- `tools/`: Supporting observability and debugging tools; useful for ecosystem context and validation workflows.
- `services/`: Integration paths for running SCX artifacts as managed services.
- `scripts/`: Developer-focused helper scripts (trace/export/debug utilities).
- `.github/`: CI definition; source of truth for format/check/test/verifier expectations.
- `.nix/`: Pinned environment and kernel build/testing reproducibility support.
- `docs/`, `agents/`, `work/`: Collaboration framework for humans and coding agents in this repo.

## Layer 1: SCX framework

At a high level, this repository has three cooperating layers:

1. Kernel-facing scheduler logic in BPF (`scheds/.../src/bpf/*.bpf.c` and shared headers).
2. Userspace Rust binaries that load and manage BPF schedulers (`scheds/rust/*/src/main.rs`).
3. Shared infra and tooling (`rust/*`, `tools/*`, CI in `.github/workflows/ci.yml`).

Common lifecycle for Rust schedulers:

- open BPF object
- load/verify BPF programs and maps
- attach `struct_ops` scheduler
- run userspace loop / telemetry
- detach and exit cleanly

`scx_invariant` follows this same lifecycle while focusing on trace collection.

## Layer 2: `scx_invariant` detailed flow

### Control plane

- `src/main.rs` parses `--output`, builds CPU topology, installs Ctrl-C shutdown handler, and manages scheduler lifecycle.
- `Scheduler::init()` opens, loads, and attaches `invariant_ops`.
- `Scheduler::run()` delegates event consumption and returns user-exit info.

### Data plane

- `src/bpf/main.bpf.c` produces events through ring buffers (partitioned maps).
- `src/bpf/intf.h` defines stable event structs and event type IDs.
- `src/recorder.rs` polls ring buffers and forwards raw payloads to the writer.
- `src/output.rs` writes the binary `SCXI` file:
  - file header (`SCXI` magic, metadata)
  - topology section
  - events section (TLV stream)
  - process table section at finalize
- `analysis/reader.py` parses and summarizes produced traces.

## Contract boundaries

- `intf.h` and `output.rs` define the producer side of the on-disk contract.
- `analysis/reader.py` defines a consumer implementation of the same contract.
- Any format-affecting change must update both sides and preserve backward expectations unless the task explicitly allows a format break.

## Safety boundaries

- Treat `scx_invariant` as profiling-first:
  - keep scheduler behavior close to passthrough defaults,
  - avoid policy decisions as part of profiling work.
- If policy behavior must change, the task should state why and include explicit validation requirements.

