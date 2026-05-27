# Pipeleek Copilot Agent Modes

This document defines maintainer-oriented execution modes for Copilot work in this repository.

## command-implementation

### When to use

Use when implementing or modifying an existing command and you need the repository-standard command structure.

### Inputs required

- Touched command file paths.
- Flag-to-config key bindings.
- Required key list and validator expectations.
- Parent command registration path and expected CLI behavior.

### Expected outputs

- Command follows `config.NewCommandSetup` and current repository conventions.
- Required keys validated.
- Values read via unified config getters.
- Parent command registration, tests, and docs are updated when applicable.

### Validation checklist

1. Run focused unit tests for touched command packages.
2. Confirm command is registered in the expected parent tree.
3. Confirm no direct `cmd.Flags().Get*` reads remain in touched execution paths.

## command-coverage

### When to use

Use for requests that affect "all commands" under a platform.

### Inputs required

- Platform root path under `internal/cmd/<platform>/`.
- Requested behavior change to apply.
- Any explicit exclusions from maintainers.

### Expected outputs

- Recursive command tree discovered under `internal/cmd/<platform>/`.
- Scan and non-scan commands updated, including nested children.
- No in-scope command directories skipped.

### Validation checklist

1. Spot-check command directories under the target platform.
2. Verify nested command groups are covered or explicitly marked not applicable.
3. Run targeted tests for multiple affected command groups.

## docs-sync

### When to use

Use when flags, config keys, or command semantics are updated.

### Inputs required

- Changed command files and affected flags.
- Changed config keys and inheritance impact.
- Affected docs sections and examples.

### Expected outputs

- docs/introduction/configuration.md updated if key usage changed.
- User-facing guides updated where behavior or examples changed.
- Generated config output expectations reviewed.

### Validation checklist

1. Verify docs examples match command flags and key names.
2. Verify links and section references resolve.
3. Confirm stale flag references were removed from touched docs.

## new-command

### When to use

Use when adding a new CLI command or subcommand.
Apply the `command-implementation` mode as the baseline, then add the creation-specific work in this mode.

### Inputs required

- Target platform and command path under `internal/cmd/<platform>/`.
- Required flags and config keys.
- Behavior intent and output expectations.

### Expected outputs

- New command added with Cobra wiring and consistent flag naming.
- Command uses `config.NewCommandSetup` with bindings, required keys, and validators.
- Unit tests and e2e tests added or updated for command behavior.
- Each flag defined on the new command is covered by at least one useful e2e test that asserts behavior.
- Documentation updated for flags/config keys and usage examples.

### Validation checklist

1. Confirm command is registered in the correct parent command tree.
2. Confirm config bindings, required keys, and validators are complete.
3. Confirm unit tests and e2e tests for the new command path pass.
4. Confirm each flag defined on the new command has at least one behavior-asserting e2e test.
5. Confirm docs and configuration references are synchronized.

## pr-review-fixes

### When to use

Use when a pull request has review comments that require code changes and thread resolution.

### Inputs required

- Active PR context and changed files.
- Review comments/threads to address.
- Any explicit reviewer constraints or requested behavior.

### Expected outputs

- Review feedback converted into concrete code changes.
- Requested behavior and edge cases addressed in code/tests.
- Response summary maps each fix to the corresponding review thread.

### Validation checklist

1. Fetch and triage open review comments before editing.
2. Apply fixes with minimal behavioral regression risk.
3. Run focused tests for touched areas.
4. Confirm each addressed thread has a clear resolution note.

## pr-actions-debug-fixes

### When to use

Use when PR status checks fail and maintainers need local reproduction, diagnosis, and fixes.

### Inputs required

- Failing workflow/check names and failure logs.
- PR branch diff context.
- Local commands needed to reproduce failing jobs.

### Expected outputs

- Root cause identified for each failing check.
- Local reproduction command(s) documented.
- Minimal fix set applied and validated locally.
- Follow-up risk or non-reproducible gaps explicitly noted.

### Validation checklist

1. Extract failing checks and logs before patching.
2. Reproduce failure locally with the closest equivalent command.
3. Apply fix and rerun relevant local validation.
4. Report what passed, what remains unverified, and why.
