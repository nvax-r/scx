# Bugfix Prompt Template (`scx_invariant`)

Use this template when asking an implementation agent to fix a bug.

---

You are fixing a bug in `scx_invariant`.

## Mandatory pre-read
Read in order before coding:
1. `docs/overview.md`
2. `docs/architecture.md`
3. `docs/conventions.md`
4. `docs/eval.md`
5. `docs/glossary.md`
6. `work/task.md`

## Scope
- Understand whole SCX context.
- Restrict scheduler-specific edits to `scheds/rust/scx_invariant` unless explicitly expanded.
- Preserve scheduling behavior by default (profiling-first).

## Task
- Problem statement: <fill from `work/task.md`>
- Expected behavior: <fill>
- Non-goals: <fill>

## Required validation
- Run relevant commands from `docs/eval.md`.
- If trace/event format is touched, validate producer/consumer consistency.

## Deliverables
- Minimal patch addressing root cause.
- Update `work/notes.md` with diagnosis and verification evidence.
- Update `work/changelog.md` with concise change summary.

---

