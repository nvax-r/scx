# AGENTS

This file is the root entrypoint for coding agents working in this repository.

## Mandatory docs-first onboarding

Read these files in order before any implementation or review:

1. `scheds/rust/scx_invariant/PLAN.md` — project plan, architecture, final goal
2. `docs/overview.md`
3. `docs/architecture.md`
4. `docs/conventions.md`
5. `docs/eval.md`
6. `docs/glossary.md`
7. Ask user where is the repo of the corresponding linux kernel, don't guess by yourself

Then you MUST read:

8. `kernel/sched/ext.c` in the kernel code, and understand the bpf subsystem
9. `agents/program.md` (for implementation) or `agents/reviewer.md` (for review)
10. `work/task.md` (human-authored task source of truth)

`PLAN.md` is the authoritative reference for *what* the project is building and *why* — including the per-task / per-workload analysis layer that is the eventual deliverable. Every contributor should understand the full goal before touching code.

## Scope and safety

- Understand the whole SCX framework.
- Never modify files outside `scheds/rust/scx_invariant` by default.
- Exception: edits outside `scx_invariant` are allowed only when truly necessary to complete the task safely, and must be explicitly justified in `work/notes.md`.
- `scx_invariant` is profiling-first; avoid scheduling policy changes unless explicitly required and justified by the task.

## Workflow files

- `work/task.md`: intentionally human-authored, may be empty between tasks.
- `work/notes.md`: investigation notes and evidence.
- `work/changelog.md`: concise record of completed deltas.

