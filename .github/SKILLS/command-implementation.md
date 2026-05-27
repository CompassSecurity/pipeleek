# Skill: Command Implementation Guidelines

## When to use

Use this skill when implementing or modifying a command in Pipeleek and you need to follow the repository-standard command shape.

Core rule: treat `config.NewCommandSetup` and `WithFlagBindings` as a paired pattern. Do not use one without the other for consumed flags.

## Inputs required

- Target command file path under `internal/cmd/<platform>/`.
- Parent command registration path.
- Required flags and mapped config keys.
- Expected behavior, validation needs, and test scope.

## Procedure

1. Place command logic under the appropriate `internal/cmd/<platform>/` path.
2. Register the command under the correct parent command.
3. Use `config.NewCommandSetup(cmd)` for bindings and validation.
4. Map every consumed flag with `WithFlagBindings`.
5. Use `RequireKeys` for mandatory values.
6. Add validators for URL, token, thread count, or command-specific constraints as needed.
7. Read values with config getters instead of direct flag access.
8. Add or update focused tests for the touched command path.
9. Update docs when flags, keys, or user-visible command behavior changes.

## Expected outputs

1. Command structure matches repository conventions.
2. Config loading and validation follow the current standard.
3. Tests cover the command path that changed.
4. Docs stay aligned with command flags and config keys.

## Acceptance checklist

- Command is registered in the correct parent tree.
- No `cmd.Flags().Get*` reads remain in command execution logic.
- Required keys and validators are defined where needed.
- Focused tests for touched command packages pass.
- `docs/introduction/configuration.md` is updated when key or flag semantics change.

## Non-goals

1. Do not introduce legacy config binding patterns.
2. Do not leave parent command registration incomplete.
3. Do not skip tests or docs for user-visible command changes.