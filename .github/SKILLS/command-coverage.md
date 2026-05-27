# Skill: Recursive Platform Command Coverage

## When to use

Use this skill when a request targets all commands for a platform or a broad platform-wide behavior.

## Inputs required

- Platform root under `internal/cmd/<platform>/`.
- Change criteria (what must be updated across commands).
- Any exclusions explicitly requested by maintainers.

## Procedure

1. Enumerate command files recursively under the platform directory.
2. Group commands by command tree (for example: scan, renovate/*, runners/*).
3. Identify all run entrypoints impacted by the requested change.
4. Apply updates consistently across scan and non-scan commands.
5. Verify nested command groups were not skipped.

## Expected outputs

1. Full recursive platform scope is covered unless exclusions are explicitly provided.
2. Scan and non-scan command trees receive the requested update consistently.
3. Coverage is reported by command groups in the implementation summary.

## Acceptance checklist

- All in-scope command groups are touched or explicitly marked not applicable.
- No partial rollout to only scan commands when broader scope was requested.
- Follow-up tests cover more than one command group when possible.

## Non-goals

1. Do not assume exclusions without explicit maintainer input.
2. Do not stop at top-level command files if nested groups exist.
