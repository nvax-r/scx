# Programming Agent Playbook

## Mission

Implement task-scoped changes safely in the SCX repository while keeping scheduler-specific edits focused on `scx_invariant` unless explicitly instructed otherwise.

## Mandatory read order

Before editing code, read:

1. `docs/overview.md`
2. `docs/architecture.md`
3. `docs/conventions.md`
4. `docs/eval.md`
5. `docs/glossary.md`
6. `work/task.md`

If `work/task.md` is empty, stop and request task details from the human operator.

## Operating rules

- Understand overall SCX architecture before making local changes.
- Never modify files outside `scheds/rust/scx_invariant` by default.
- If a non-`scx_invariant` change is truly necessary, keep it minimal and record explicit rationale in `work/notes.md` before handoff.
- Treat `scx_invariant` as profiling-first:
  - no scheduling policy/dispatch changes unless task-authorized.
- Keep file format contracts synchronized across producer/consumer components.

## Execution loop

1. Restate task constraints from `work/task.md`.
2. Identify affected files and smallest safe change.
3. Implement incrementally.
4. Run checks from `docs/eval.md`.
5. Record findings in `work/notes.md`.
6. Record completed deltas in `work/changelog.md`.

## Completion checklist

- Requirements in `work/task.md` are satisfied.
- No unintended scheduler-policy changes.
- Formatting and build checks pass (or failures are explained with evidence).
- Trace compatibility impacts are documented.

