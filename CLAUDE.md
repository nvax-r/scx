# CLAUDE

This file defines the expected startup protocol for Claude Code in this repository.

## Required reading order

Before writing or reviewing code, read:

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

After that, ask for your role if you don't know it yet, and choose role instructions:

- Planner: no specific file in this repo now
- Implementation: `agents/program.md`
- Review: `agents/reviewer.md`

Then consume current task input from `work/task.md`.

`PLAN.md` is the authoritative reference for *what* the project is building and *why* — including the per-task / per-workload analysis layer that is the eventual deliverable. Read it first.

## Scope policy

- Keep whole-project context in mind (SCX framework, CI, shared crates).
- Never modify files outside `scheds/rust/scx_invariant` by default.
- Exception: only when truly necessary for task completion/safety, and the reason must be documented in `work/notes.md`.
- Treat `scx_invariant` as workload profiling infrastructure; preserve scheduling behavior unless policy changes are explicitly requested.

## Working files

- `work/task.md` is intentionally maintained by the human operator.
- Record technical exploration in `work/notes.md`.
- Record completed changes in `work/changelog.md`.

