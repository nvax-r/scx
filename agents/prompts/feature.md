# Feature Prompt Template (`scx_invariant`)

Use this template for new `scx_invariant` capabilities.

---

You are implementing a feature in `scx_invariant`.

## Mandatory pre-read
Read in order before coding:
1. `docs/overview.md`
2. `docs/architecture.md`
3. `docs/conventions.md`
4. `docs/eval.md`
5. `docs/glossary.md`
6. `work/task.md`

## Scope and safety
- Build understanding from whole SCX framework.
- Keep scheduler-specific edits within `scheds/rust/scx_invariant` unless task expands scope.
- `scx_invariant` is profiling-first; avoid policy/dispatch changes unless explicitly required and justified.

## Task details
- Feature goal: <fill from `work/task.md`>
- User-visible behavior: <fill>
- Constraints: <fill>
- Compatibility expectations: <fill>

## Required validation
- Execute relevant checks in `docs/eval.md`.
- Provide trace/readout evidence when feature affects event recording or analysis.

## Deliverables
- Incremental implementation with clear rationale.
- `work/notes.md` updated with design decisions and validation output.
- `work/changelog.md` updated with concise outcome and follow-ups.

---

