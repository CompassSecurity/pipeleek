# Skill: Docs and Config Synchronization

## When to use

Use this skill when adding/changing flags, config keys, or command behavior that affects user docs.

## Inputs required

- Changed command files.
- Changed flags and key names.
- Affected user-facing docs sections.

## Procedure

1. Update docs/introduction/configuration.md for new or changed config keys.
2. Verify examples use current flags and key names.
3. Check related guides for stale command invocations.
4. Confirm command help output and docs examples are aligned.

## Expected outputs

1. Configuration docs reflect the current key model and inheritance behavior.
2. Guides and examples use current command syntax.
3. Stale flag or key references are removed from touched docs.

## Acceptance checklist

- Configuration docs match current key naming and inheritance behavior.
- Guides reflect current command syntax.
- No stale flags remain in updated sections.

## Non-goals

1. Do not rewrite unrelated documentation sections.
2. Do not leave config or guide examples in a mixed old/new state.
