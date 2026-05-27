# Skill: Creating a New Command

## When to use

Use this skill when implementing a new command or subcommand in the Pipeleek CLI.

This skill builds on `.github/SKILLS/command-implementation.md` and adds the extra requirements that are specific to creating a brand new command.

## Inputs required

- Target command path under `internal/cmd/<platform>/`.
- Command name, purpose, and expected output.
- Required flags and mapped config keys.
- Validation requirements and test scope.

## Relationship to command-implementation

Apply `.github/SKILLS/command-implementation.md` as the baseline for command structure, config binding, validators, and docs sync.
Use this skill for the additional creation-specific work below.

## Procedure

1. Add the command file in the appropriate `internal/cmd/<platform>/` directory.
2. Register the new command under the correct parent command.
3. Add unit tests for the command path.
4. Add e2e tests for the command path.
5. Ensure each flag defined on the new command has at least one useful e2e test that asserts behavior.
6. Update docs and config guidance when flags/keys are added.

## Expected outputs

1. New command is accessible via the intended command path.
2. Base command implementation follows repository standards.
3. Unit tests and e2e tests cover the new command behavior.
4. Each command-defined flag is exercised by at least one behavior-asserting e2e test.
5. User-facing docs reflect the new command syntax and config keys.

## Acceptance checklist

- Command is discoverable in help output under the expected parent.
- `command-implementation` requirements are satisfied.
- Unit tests for the touched command path pass.
- E2E tests for the touched command path pass.
- Each flag defined on the new command has at least one useful e2e test that asserts behavior.
- `docs/introduction/configuration.md` is updated when key/flag semantics change.

## Non-goals

1. Do not mix legacy config binding patterns in the new command.
2. Do not skip command registration in parent command trees.
3. Do not leave docs or tests unaddressed for user-visible command additions.
