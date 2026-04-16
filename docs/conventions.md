# Conventions for Human + Agent Collaboration

## Priority order

1. Correctness and safety.
2. Preserve existing behavior (especially scheduler behavior in `scx_invariant`).
3. Keep changes minimal and auditable.
4. Keep docs/tests aligned with code changes.

## Scope conventions

- Understand the whole SCX repo before editing.
- Never modify files outside `scheds/rust/scx_invariant` by default.
- Exception: changes outside `scx_invariant` are permitted only when truly necessary, minimal, and explicitly justified in `work/notes.md`.
- Other schedulers may be used for reference only by default.

## `scx_invariant` conventions

- Treat it as a workload profiling tool first.
- Do not introduce scheduling policy changes unless explicitly requested and justified.
- Keep trace format changes synchronized across:
  - `src/bpf/intf.h`
  - `src/output.rs`
  - `analysis/reader.py`

## Coding conventions

- Follow repository style and run formatting/check commands before handoff.
- Prefer small, focused commits and clear rationale.
- Do not add hidden behavior or speculative abstractions.

## CI-aligned local checks

Use these as default local checks before proposing completion:

- `cargo fmt --check`
- `cargo check --profile ci --locked`
- `cargo nextest run --cargo-profile ci --workspace --locked --no-fail-fast --status-level fail --success-output never`

`scx_invariant` is part of workspace checks, but not all scheduler runtime test matrices include it by default. For scheduler-local validation, run targeted commands described in `docs/eval.md`.

## Worklog conventions

- `work/task.md`: human-authored objective and acceptance criteria (agents read, do not overwrite intent).
- `work/notes.md`: investigation notes, hypotheses, command snippets, findings.
- `work/changelog.md`: concise, chronological summary of implemented deltas.

