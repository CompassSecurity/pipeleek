# Skill: Debug PR Actions Failures and Apply Fixes Locally

## When to use

Use this skill when GitHub Actions checks fail on a PR and maintainers need local diagnosis and fixes.

## Inputs required

- Failing check names and job/workflow logs.
- PR diff context and touched files.
- Local equivalents of CI commands (test, lint, build, docs).

## Procedure

1. Collect failing checks and extract primary error messages.
2. Identify likely failure class: test failure, lint failure, build failure, docs/generation drift, or environment mismatch.
3. Reproduce each failure locally using closest equivalent command.
4. Apply minimal fixes to remove root cause.
5. Rerun relevant local checks after each fix.
6. Record which failures were reproduced, fixed, and verified.
7. If not reproducible, document likely causes and confidence level.

## Expected outputs

1. Root cause identified for each failing check where possible.
2. Minimal patch set addresses failing checks.
3. Local validation commands and outcomes are documented.
4. Remaining risk is called out for non-reproducible failures.

## Acceptance checklist

- Failing checks/log evidence reviewed before code changes.
- At least one local reproduction command attempted per failing class.
- Post-fix local checks pass for impacted areas.
- Final summary includes fixed items and unresolved risks.

## Non-goals

1. Do not guess fixes without correlating to failure logs.
2. Do not ignore non-reproducible failures; document them explicitly.
3. Do not perform unrelated cleanups while stabilizing failing checks.
