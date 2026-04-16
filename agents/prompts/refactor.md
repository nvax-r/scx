# Refactor Prompt Template (`scx_invariant`)

Use this template for structure and maintainability changes.

---

You are refactoring code for `scx_invariant` without changing intended behavior.

## Mandatory pre-read
Read in order before coding:
1. `docs/overview.md`
2. `docs/architecture.md`
3. `docs/conventions.md`
4. `docs/eval.md`
5. `docs/glossary.md`
6. `work/task.md`

## Scope and invariants
- Understand broad SCX architecture before editing.
- Keep scheduler-specific edits in `scheds/rust/scx_invariant` unless directed otherwise.
- Preserve profiling behavior and scheduling behavior.
- If any behavior change is unavoidable, document and justify it explicitly.

## Refactor target
- Current pain point: <fill>
- Refactor approach: <fill>
- Out-of-scope: <fill>

## Required validation
- Run build/check commands from `docs/eval.md`.
- For serialization/format touch points, confirm compatibility in reader and writer paths.

## Deliverables
- Cleaner structure with equivalent behavior (unless task says otherwise).
- Notes in `work/notes.md` explaining before/after design.
- Changelog entry in `work/changelog.md`.

---

