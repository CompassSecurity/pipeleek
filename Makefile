.PHONY: help build build-all build-gitlab build-github build-bitbucket build-devops build-gitea test test-unit test-e2e lint clean coverage coverage-html serve-docs

# Default target
help:
	@echo "Pipeleek Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make build            - Build the main pipeleek binary"
	@echo "  make build-all        - Build all binaries (main + platform-specific)"
	@echo "  make build-gitlab     - Build GitLab-specific binary"
	@echo "  make build-github     - Build GitHub-specific binary"
	@echo "  make build-bitbucket  - Build BitBucket-specific binary"
	@echo "  make build-devops     - Build Azure DevOps-specific binary"
	@echo "  make build-gitea      - Build Gitea-specific binary"
	@echo "  make test             - Run all tests (unit + e2e)"
	@echo "  make test-unit        - Run unit tests only"
	@echo "  make test-e2e         - Run e2e tests (builds binary first)"
	@echo "  make coverage         - Generate test coverage report"
	@echo "  make coverage-html    - Generate and open HTML coverage report"
	@echo "  make lint             - Run golangci-lint"
	@echo "  make serve-docs       - Generate and serve CLI documentation"
	@echo "  make clean            - Remove built artifacts"

# Build the main pipeleek binary
build:
	@echo "Building pipeleek..."
	CGO_ENABLED=0 go build -o pipeleek ./cmd/pipeleek

# Build GitLab-specific binary
build-gitlab:
	@echo "Building pipeleek-gitlab..."
	CGO_ENABLED=0 go build -o pipeleek-gitlab ./cmd/pipeleek-gitlab

# Build GitHub-specific binary
build-github:
	@echo "Building pipeleek-github..."
	CGO_ENABLED=0 go build -o pipeleek-github ./cmd/pipeleek-github

# Build BitBucket-specific binary
build-bitbucket:
	@echo "Building pipeleek-bitbucket..."
	CGO_ENABLED=0 go build -o pipeleek-bitbucket ./cmd/pipeleek-bitbucket

# Build Azure DevOps-specific binary
build-devops:
	@echo "Building pipeleek-devops..."
	CGO_ENABLED=0 go build -o pipeleek-devops ./cmd/pipeleek-devops

# Build Gitea-specific binary
build-gitea:
	@echo "Building pipeleek-gitea..."
	CGO_ENABLED=0 go build -o pipeleek-gitea ./cmd/pipeleek-gitea

# Build all binaries
build-all: build build-gitlab build-github build-bitbucket build-devops build-gitea
	@echo "All binaries built successfully"

# Run all tests
test: test-unit test-e2e

# Run unit tests (excluding e2e)
test-unit:
	@echo "Running unit tests..."
	go test $$(go list ./... | grep -v /tests/e2e) -v -race

# Run e2e tests (builds binary first)
test-e2e: build
	@echo "Running e2e tests..."
	PIPELEEK_BINARY=$$(pwd)/pipeleek go test ./tests/e2e/... -tags=e2e -v -timeout 10m

# Run e2e tests for specific platform
test-e2e-gitlab: build
	@echo "Running GitLab e2e tests..."
	PIPELEEK_BINARY=$$(pwd)/pipeleek go test ./tests/e2e/gitlab/... -tags=e2e -v

test-e2e-github: build
	@echo "Running GitHub e2e tests..."
	PIPELEEK_BINARY=$$(pwd)/pipeleek go test ./tests/e2e/github/... -tags=e2e -v

test-e2e-bitbucket: build
	@echo "Running BitBucket e2e tests..."
	PIPELEEK_BINARY=$$(pwd)/pipeleek go test ./tests/e2e/bitbucket/... -tags=e2e -v

test-e2e-devops: build
	@echo "Running Azure DevOps e2e tests..."
	PIPELEEK_BINARY=$$(pwd)/pipeleek go test ./tests/e2e/devops/... -tags=e2e -v

test-e2e-gitea: build
	@echo "Running Gitea e2e tests..."
	PIPELEEK_BINARY=$$(pwd)/pipeleek go test ./tests/e2e/gitea/... -tags=e2e -v

# Generate test coverage report
coverage:
	@echo "Generating coverage report..."
	@go test $$(go list ./... | grep -v /tests/e2e) -coverprofile=coverage.out -covermode=atomic
	@echo ""
	@echo "Coverage Summary:"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total Coverage: " $$3}'
	@echo ""
	@echo "Coverage report saved to coverage.out"
	@echo "Run 'make coverage-html' to view detailed HTML report"

# Generate and open HTML coverage report
coverage-html: coverage
	@echo "Generating HTML coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report saved to coverage.html"
	@if command -v xdg-open > /dev/null; then \
		xdg-open coverage.html; \
	elif command -v open > /dev/null; then \
		open coverage.html; \
	else \
		echo "Open coverage.html in your browser to view the report"; \
	fi

# Run golangci-lint
lint:
	@echo "Running golangci-lint..."
	golangci-lint run --timeout=10m

# Generate and serve CLI documentation
serve-docs: build
	@echo "Generating and serving CLI documentation..."
	@if ! command -v mkdocs > /dev/null 2>&1; then \
		echo "MkDocs not found. Installing MkDocs and dependencies..."; \
		pip install mkdocs mkdocs-material mkdocs-minify-plugin; \
	fi
	./pipeleek docs -s

# Clean up built artifacts
clean:
	@echo "Cleaning up..."
	rm -f pipeleek pipeleek.exe coverage.out coverage.html
	rm -f pipeleek-gitlab pipeleek-gitlab.exe
	rm -f pipeleek-github pipeleek-github.exe
	rm -f pipeleek-bitbucket pipeleek-bitbucket.exe
	rm -f pipeleek-devops pipeleek-devops.exe
	rm -f pipeleek-gitea pipeleek-gitea.exe
	go clean -cache -testcache
