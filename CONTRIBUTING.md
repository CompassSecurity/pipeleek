# Contributing to Pipeleek

Thank you for your interest in contributing to Pipeleek! This guide will help you get started with the development environment and provide guidelines for contributing.

## Getting Started with GitHub Codespaces

The fastest way to start contributing is using GitHub Codespaces:

1. Click the "Code" button on the repository page
2. Select the "Codespaces" tab
3. Click "Create codespace on main" (or your branch)

The codespace will automatically:

- Set up Go 1.24+ environment
- Install golangci-lint for code linting
- Install Python and MkDocs for documentation
- Download all Go dependencies
- Build the pipeleek binary

Once the codespace is ready, you can start working immediately since the Go module is at the repository root.

## Local Development Setup

If you prefer local development:

### Prerequisites

- Go 1.24 or higher
- golangci-lint (for linting)
- Python 3.x with pip (for documentation)

### Setup Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/CompassSecurity/pipeleek.git
   cd pipeleek
   ```

2. Install golangci-lint:

   ```bash
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   ```

3. Download dependencies:

   ```bash
   go mod download
   ```

4. Run it:

   ```bash
   go run cmd/pipeleek/main.go
   ```

5. Optional: Build the binary:
   ```bash
   make build
   ```

## Development Workflow

### Building

```bash
make build
```

### Running Tests

```bash
# Run all tests (unit + e2e)
make test

# Run unit tests only
make test-unit

# Run e2e tests
make test-e2e

# Run e2e tests for specific platform
make test-e2e-gitlab
make test-e2e-github
make test-e2e-bitbucket
make test-e2e-devops
make test-e2e-gitea
```

### Linting

```bash
make lint
```

### Test Coverage

```bash
# Generate coverage report
make coverage

# Generate and view HTML coverage report
make coverage-html
```

### Documentation

```bash
# Generate and serve documentation locally
make serve-docs
```

## Project Structure

```
pipeleek/
├── cmd/pipeleek/           # CLI entry point (main.go)
├── internal/cmd/           # CLI commands (Cobra) - internal package
│   ├── bitbucket/          # BitBucket commands
│   ├── devops/             # Azure DevOps commands
│   ├── flags/              # Common CLI flags
│   ├── gitea/              # Gitea commands
│   ├── github/             # GitHub commands
│   ├── gitlab/             # GitLab commands
├── pkg/                    # Core business logic
├── tests/e2e/              # End-to-end tests
├── docs/                   # Documentation (MkDocs)
├── go.mod                  # Go module definition
├── Makefile                # Build commands
└── .devcontainer/          # GitHub Codespaces config
```

## Code Guidelines

### General

- Follow standard Go conventions and idioms
- Use `zerolog` for structured logging
- Write tests for new functionality
- Keep CLI commands in `internal/cmd/` and business logic in `pkg/`

### Commit Messages

- Use clear, descriptive commit messages
- Reference issue numbers when applicable

### Pull Requests

1. Create a feature branch from `main`
2. Make your changes with appropriate tests
3. Ensure all tests pass: `make test`
4. Ensure linting passes: `make lint`
5. Submit a pull request with a clear description

### Testing

- Write table-driven tests where appropriate
- Use `testify/assert` for assertions
- Place unit tests next to the code they test
- Place e2e tests in `tests/e2e/`
- Use `t.Parallel()` where safe
- Use `t.TempDir()` for temporary files

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Join discussions in pull requests

## License

By contributing, you agree that your contributions will be licensed under the project's license.
