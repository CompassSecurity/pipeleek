# Skill: Address PR Review Comments and Apply Fixes

## When to use

Use this skill when a PR has open review comments requiring code, tests, or documentation updates.

## Inputs required

- Active PR details and changed files.
- Open review threads/comments and reviewer expectations.
- Any scope limits or non-goals provided by maintainers.

## Procedure

1. Fetch active PR review comments and group by concern.
2. Classify comments into: correctness bug, regression risk, test gap, docs gap, or style.
3. Prioritize correctness and regression risks first.
4. Apply minimal, targeted fixes for each accepted review concern.
5. Add tests when comments imply missing coverage or edge cases.
6. Update docs when behavior/flags/config semantics changed.
7. Prepare a per-thread resolution summary mapping comment to code change and validation.

## Expected outputs

1. Open review concerns are translated into concrete, traceable fixes.
2. High-severity concerns are addressed first.
3. Validation evidence is available for each meaningful fix.
4. Unresolved or deferred comments are explicitly documented with reason.

## Acceptance checklist

- Every open review comment is triaged (fixed, deferred, or rejected with rationale).
- Fixes are scoped to requested concerns and avoid unrelated refactors.
- Focused tests pass for touched areas.
- Resolution summary maps comment -> fix -> validation command(s).

## Non-goals

1. Do not resolve threads without applying or justifying the requested change.
2. Do not introduce broad style-only refactors while addressing review comments.
3. Do not skip test updates when reviewer feedback indicates coverage gaps.
