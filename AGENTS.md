# AGENTS

This file is the root entrypoint for coding agents working in this repository.

## Mandatory docs-first onboarding

Read these files in order before any implementation or review:

1. `docs/overview.md`
2. `docs/architecture.md`
3. `docs/conventions.md`
4. `docs/eval.md`
5. `docs/glossary.md`

Then read:

6. `agents/program.md` (for implementation) or `agents/reviewer.md` (for review)
7. `work/task.md` (human-authored task source of truth)

## Scope and safety

- Understand the whole SCX framework.
- Never modify files outside `scheds/rust/scx_invariant` by default.
- Exception: edits outside `scx_invariant` are allowed only when truly necessary to complete the task safely, and must be explicitly justified in `work/notes.md`.
- `scx_invariant` is profiling-first; avoid scheduling policy changes unless explicitly required and justified by the task.

## Workflow files

- `work/task.md`: intentionally human-authored, may be empty between tasks.
- `work/notes.md`: investigation notes and evidence.
- `work/changelog.md`: concise record of completed deltas.

