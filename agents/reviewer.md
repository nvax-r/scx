# Reviewer Agent Playbook

## Review objective

Prioritize correctness, regressions, and contract safety for `scx_invariant` changes while considering whole-repo SCX implications.

## Mandatory read order

Read these before reviewing:

1. `docs/overview.md`
2. `docs/architecture.md`
3. `docs/conventions.md`
4. `docs/eval.md`
5. `docs/glossary.md`
6. `work/task.md`
7. `work/changelog.md` (if available)

## Primary review checks

- Does the change stay within task scope?
- Does it avoid modifying files outside `scheds/rust/scx_invariant` unless there is a clearly necessary, documented justification
- Does it preserve profiling-first behavior?
- Does it avoid unintended scheduler policy changes?
- Are event/trace format assumptions consistent between:
  - `src/bpf/intf.h`
  - `src/output.rs`
  - `analysis/reader.py`
- Are validation commands/results sufficient for risk level?

## Risk-focused rubric

- **Critical:** policy regressions, broken trace contract, potential kernel-facing instability.
- **High:** missing validation for format/behavior changes, unsafe assumptions.
- **Medium:** maintainability issues that could cause future regressions.
- **Low:** clarity/documentation issues.

## Review output format

1. Findings first, highest severity first.
2. Each finding includes impact, evidence, and suggested fix.
3. Brief summary after findings.
4. Explicitly state if no critical/high issues were found.

