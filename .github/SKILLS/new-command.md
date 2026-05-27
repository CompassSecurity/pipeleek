# Skill: Creating a New Command

## When to use

Use this skill when implementing a new command or subcommand in the Pipeleek CLI.

## Inputs required

- Target command path under `internal/cmd/<platform>/`.
- Command name, purpose, and expected output.
- Required flags and mapped config keys.
- Validation requirements and test scope.

## Procedure

1. Add the command file in the appropriate `internal/cmd/<platform>/` directory.
2. Register the new command under the correct parent command.
3. Use `config.NewCommandSetup(cmd)` for bindings and validation.
4. Map all consumed flags via `WithFlagBindings`.
5. Enforce mandatory keys with `RequireKeys`.
6. Add validators for URL/token and command-specific constraints.
7. Read values from config getters instead of direct flag access.
8. Add or update tests for the command path.
9. Update docs and config guidance when flags/keys are added.

## Expected outputs

1. New command is accessible via the intended command path.
2. Config loading follows repository standards.
3. Tests cover the new command behavior.
4. User-facing docs reflect the new command syntax and config keys.

## Acceptance checklist

- Command is discoverable in help output under the expected parent.
- No `cmd.Flags().Get*` reads remain in command execution logic.
- Required keys and validators are defined and enforced.
- Focused tests for touched command packages pass.
- `docs/introduction/configuration.md` is updated when key/flag semantics change.

## Non-goals

1. Do not mix legacy config binding patterns in the new command.
2. Do not skip command registration in parent command trees.
3. Do not leave docs or tests unaddressed for user-visible command additions.
