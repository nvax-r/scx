# Reviewer Agent Playbook

## Review objective

Prioritize correctness, regressions, and contract safety for `scx_invariant` changes while considering whole-repo SCX implications.

## Mandatory read order

Read these before reviewing:

1. `scheds/rust/scx_invariant/PLAN.md` — project plan, architecture, final goal
2. `docs/overview.md`
3. `docs/architecture.md`
4. `docs/conventions.md`
5. `docs/eval.md`
6. `docs/glossary.md`
7. `work/task.md`
8. `work/changelog.md` (if available)

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

## Reviewer responsibility: DEEP review, not a rubber stamp

The review is the last line of defense before a change lands. Do not merely
confirm the implementer's claims or echo their self-description. Treat every
change as if it will ship to production and you will be the one debugging it
at 2 a.m. if it breaks.

For every change, **actively hunt** for:

- **Bugs** — logic errors, off-by-one, wrong sign, wrong type, wrong bit,
  zero-init assumptions, integer overflow, signed/unsigned mistakes, race
  conditions, missing NULL checks, unchecked return values, incorrect
  lifecycle ordering, stale state carried across events.
- **Regressions** — does this break existing behavior? Does it change the
  semantics of an existing event, field, or API without the reader/consumer
  being updated in lockstep? Does it perturb scheduling in any way?
- **Coding issues** — unclear naming, dead code, duplicated logic, missing
  cleanup, magic numbers, missing comments on non-obvious invariants, struct
  layout mismatches across the intf.h / output.rs / reader.py boundary,
  inefficient hot-path patterns, verifier-hostile BPF constructs.
- **Missing or weak validation** — did the implementer actually test the
  change? Did they run it on the target machine? Are the validation results
  plausible, or do they look fabricated?
- **Silent breakage risks** — anything that could fail without a loud signal:
  dropped events not counted, malformed trace files that still appear valid,
  misaligned struct fields that happen to produce reasonable-looking numbers.

**Report back to the human operator directly.** Do not close a review with
"work finished" or "implementation looks good" without enumerating what you
checked and what you found. Even a clean review must be explicit:

- List every check performed.
- Cite file:line for each finding or confirmed-safe area.
- If you found nothing, say *so explicitly and list what you inspected* so
  the operator can judge whether the review was thorough.

**Never quietly declare completion.** The report back is the deliverable. A
review with no findings is still a report; a review without a report is a
failed review.
