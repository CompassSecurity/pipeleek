# GitHub Copilot Instructions for Pipeleek

## Project Overview

Pipeleek is a CLI tool designed to scan CI/CD logs and artifacts for secrets across multiple platforms including GitLab, GitHub, BitBucket, Azure DevOps, and Gitea. The tool uses TruffleHog for secret detection and provides additional helper commands for exploitation workflows.

## Technology Stack

- **Language**: Go 1.24+
- **CLI Framework**: Cobra (github.com/spf13/cobra)
- **Logging**: Zerolog (github.com/rs/zerolog)
- **Secret Detection**: TruffleHog v3
- **Testing**: Go testing framework with testify
- **Build Tool**: Go build system
- **Release**: GoReleaser

## Project Structure

```
pipeleek/
├── cmd/pipeleek/           # CLI entry point (main.go)
├── internal/cmd/           # CLI commands (using Cobra) - internal package
│   ├── bitbucket/          # BitBucket-specific commands
│   ├── devops/             # Azure DevOps commands
│   ├── docs/               # Documentation command
│   ├── flags/              # Common CLI flags
│   ├── gitea/              # Gitea commands
│   ├── github/             # GitHub-specific commands
│   ├── gitlab/             # GitLab-specific commands
│   ├── root.go             # Root command definition
│   └── root_test.go        # Root command tests
├── pkg/                    # Core business logic packages
│   ├── archive/            # Archive handling
│   ├── bitbucket/          # BitBucket business logic
│   ├── config/             # Configuration management
│   ├── devops/             # Azure DevOps business logic
│   ├── docs/               # Documentation generation
│   ├── format/             # Formatting helpers
│   ├── gitea/              # Gitea business logic
│   ├── github/             # GitHub business logic
│   ├── gitlab/             # GitLab business logic
│   ├── httpclient/         # HTTP client helpers
│   ├── logging/            # Logging helpers
│   ├── scan/               # Scan logic
│   ├── scanner/            # Scanner engine
│   └── system/             # System helpers
├── tests/e2e/              # End-to-end tests
├── docs/                   # Documentation (MkDocs)
├── .github/                # GitHub workflows and configs
│   └── workflows/          # CI/CD pipelines
├── go.mod                  # Go module definition (at root)
├── go.sum                  # Dependency checksums
├── Makefile                # Build and test commands
└── goreleaser.yaml         # Release configuration
```

## Building and Testing

### Building the Project

```bash
make build
# Or directly:
go build -o pipeleek ./cmd/pipeleek
```

### Running Tests

**Using Makefile (recommended):**

```bash
make test           # Run all tests (unit + e2e)
make test-unit      # Run unit tests only
make test-e2e       # Run all e2e tests
```

**Unit tests (excluding e2e):**

```bash
make test-unit
# Or directly:
go test $(go list ./... | grep -v /tests/e2e) -v -race
```

**End-to-end tests:**

E2E tests are organized by platform in a structured folder hierarchy:

```
tests/e2e/
├── gitlab/          # GitLab-specific tests
│   ├── cicd/yaml/   # CICD YAML command tests
│   ├── scan/        # Scan command tests
│   ├── variables/   # Variables command tests
│   ├── schedule/    # Schedule command tests
│   ├── runners/     # Runners list/exploit tests
│   ├── secureFiles/ # Secure files tests
│   ├── vuln/        # Vulnerability check tests
│   ├── renovate/    # Renovate tests
│   └── unauth/      # Unauthenticated commands (shodan)
├── github/          # GitHub Actions tests
├── bitbucket/       # BitBucket tests
├── devops/          # Azure DevOps tests
├── gitea/           # Gitea tests
└── internal/        # Shared test utilities
    └── testutil/    # Common helpers (RunCLI, mock servers, etc.)
```

**Using Makefile (recommended):**

```bash
make test-e2e              # Run all e2e tests
make test-e2e-gitlab       # Run only GitLab e2e tests
make test-e2e-github       # Run only GitHub e2e tests
make test-e2e-bitbucket    # Run only BitBucket e2e tests
make test-e2e-devops       # Run only Azure DevOps e2e tests
make test-e2e-gitea        # Run only Gitea e2e tests
```

**Manual execution:**
To run e2e tests manually, first build the binary and set `PIPELEEK_BINARY`:

```bash
go build -o pipeleek ./cmd/pipeleek
PIPELEEK_BINARY=$(pwd)/pipeleek go test ./tests/e2e/... -tags=e2e -v -timeout 10m
```

Run tests for a specific platform:

```bash
# GitLab tests only
PIPELEEK_BINARY=$(pwd)/pipeleek go test ./tests/e2e/gitlab/... -tags=e2e -v

# Specific command tests
PIPELEEK_BINARY=$(pwd)/pipeleek go test ./tests/e2e/gitlab/scan -tags=e2e -v
```

**Important:** E2E tests require the `PIPELEEK_BINARY` environment variable to point to the compiled binary (absolute or relative to module root). Tests use this binary to run commands in isolated subprocesses to avoid Cobra state conflicts.

### Test Coverage

Generate and view test coverage reports:

```bash
# Generate coverage report with summary
make coverage

# Generate HTML coverage report and open in browser
make coverage-html
```

Coverage reports are stored as workflow artifacts on CI runs (Linux job). Retrieve `coverage.out` from the run's artifacts section for local inspection or HTML generation.

### Linting

The project uses golangci-lint:

```bash
make lint
# Or directly:
golangci-lint run --timeout=10m
```

### Documentation

Generate and serve CLI documentation locally:

```bash
make serve-docs  # Installs dependencies if needed, generates and serves docs
```

## Code Style and Conventions

### General Guidelines

1. **Follow Go idioms**: Use standard Go conventions and patterns
2. **Error handling**: Always check and handle errors appropriately
3. **Logging**: Use zerolog for structured logging with appropriate levels (trace, debug, info, warn, error, fatal)
4. **Testing**: Write tests for new functionality; maintain existing test coverage
5. **Documentation**: Update documentation when adding or modifying features
6. **Comments**: Only add comments that provide useful context and additional understanding; avoid obvious or redundant comments
7. **File Moves/Copies**: When moving or copying files, always delete any resulting unused or vestigial files to keep the codebase clean and maintainable.

### Command Structure

- Commands follow the Cobra pattern with `NewXCommand()` functions
- Each command should have a corresponding test file
- Commands are organized by platform (gitlab, github, bitbucket, devops, gitea)
- Use consistent flag naming across commands
- **When adding or modifying command flags**: Update both `docs/introduction/configuration.md` and `pipeleek.example.yaml` to reflect the changes

### Configuration Loading Pattern (MANDATORY)

**ALWAYS use `config.AutoBindFlags` for configuration loading in ALL commands:**

```go
func CommandRun(cmd *cobra.Command, args []string) {
    // 1. Bind flags to config keys
    if err := config.AutoBindFlags(cmd, map[string]string{
        "platform-flag": "platform.url",
        "token":         "platform.token",
        "threads":       "common.threads",
    }); err != nil {
        log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
    }

    // 2. Validate required keys
    if err := config.RequireConfigKeys("platform.url", "platform.token"); err != nil {
        log.Fatal().Err(err).Msg("required configuration missing")
    }

    // 3. Get values from unified config (supports flags/env/file)
    url := config.GetString("platform.url")
    token := config.GetString("platform.token")
    threads := config.GetInt("common.threads")
}
```

**Key naming convention:**
- Platform settings: `<platform>.<key>` (e.g., `github.url`, `gitlab.token`)
- Subcommand settings: `<platform>.<subcommand>.<key>` (e.g., `github.renovate.enum.owned`)
- Common settings: `common.<key>` (e.g., `common.threads`)

**DO NOT:**
- Read flags directly with `cmd.Flags().GetString()` - always use config system
- Use `config.BindCommandFlags` - it's deprecated in favor of `AutoBindFlags`
- Skip `RequireConfigKeys` validation for required flags

### Package Organization

- Keep business logic in `pkg/` packages
- Keep CLI interface code in `internal/cmd/` packages
- Separate concerns: commands orchestrate, packages implement

### Testing Conventions

- Test files should be named `*_test.go`
- Use table-driven tests where appropriate
- Use testify/assert for assertions
- E2E tests go in `tests/e2e/`
- Mock external dependencies in unit tests

### Logging Best Practices

- Use appropriate log levels:
  - `trace`: Very detailed diagnostic information
  - `debug`: Detailed information for debugging
  - `info`: General informational messages (default)
  - `warn`: Warning messages
  - `error`: Error conditions
  - `fatal`: Fatal errors that require program termination
  - `hit`: Special log level used exclusively for logging detected secrets
- Use structured logging with fields: `log.Info().Str("key", "value").Msg("message")`
- Log context-relevant information to aid debugging

## Dependencies

### Adding New Dependencies

1. Use `go get` to add dependencies:

   ```bash
   go get github.com/example/package@version
   ```

2. Run `go mod tidy` to clean up:

   ```bash
   go mod tidy
   ```

3. Update go.sum by running tests or building:
   ```bash
   go build ./...
   ```

### Key Dependencies

- `github.com/spf13/cobra`: CLI framework
- `github.com/rs/zerolog`: Structured logging
- `github.com/trufflesecurity/trufflehog/v3`: Secret detection
- `github.com/google/go-github/v69`: GitHub API client
- `gitlab.com/gitlab-org/api/client-go`: GitLab API client
- `code.gitea.io/sdk/gitea`: Gitea API client

## Common Development Tasks

### Adding a New Command

1. Create command file in appropriate `internal/cmd/<platform>/` directory
2. Implement command using Cobra patterns
3. Add corresponding business logic in `pkg/<platform>/`
4. Write tests for both command and business logic
5. Update documentation if needed

### Adding a New Platform

1. Create new directory under `internal/cmd/<platform>/`
2. Create corresponding package under `pkg/<platform>/`
3. Implement scan and other relevant commands
4. Add tests
5. Update documentation

### Modifying Secret Detection

- Secret detection is handled by TruffleHog
- Custom rules can be defined in `rules.yml` (user-generated)
- Confidence levels: low, medium, high, high-verified
- Verification can be disabled with `--truffle-hog-verification=false`

## CI/CD

The project uses GitHub Actions for CI/CD:

- **test.yml**: Runs unit and e2e tests on Linux and Windows
- **golangci-lint.yml**: Runs linting checks
- **release.yml**: Builds and publishes releases using GoReleaser
- **docs.yml**: Builds and deploys documentation

## Important Notes

1. **Working Directory**: The Go module is at the repository root with `go.mod`
2. **CLI Entry Point**: The main entry point is at `cmd/pipeleek/main.go`
3. **CLI Commands**: Commands are in `internal/cmd/` (internal package)
4. **Binary Names**:
   - Linux/macOS: `pipeleek`
   - Windows: `pipeleek.exe`
5. **Test Exclusions**: E2E tests are excluded from regular test runs
6. **Terminal State**: The application manages terminal state for interactive features
7. **Cross-Platform**: Code should work on Linux, macOS, and Windows

## Additional Resources

- [Getting Started Guide](https://compasssecurity.github.io/pipeleek/introduction/getting_started/)
- [GitHub Repository](https://github.com/CompassSecurity/pipeleek)
- [TruffleHog Documentation](https://github.com/trufflesecurity/trufflehog)
