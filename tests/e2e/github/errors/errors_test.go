package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGitHubScan_MissingToken(t *testing.T) {
	t.Parallel()
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "scan",
		"--github", "https://api.github.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

// TestGitHubScan_InvalidToken tests authentication error

func TestGitHubScan_InvalidToken(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, testutil.WithError(http.StatusUnauthorized, "Bad credentials"))
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "scan",
		"--github", server.URL,
		"--token", "invalid-token",
	}, nil, 10*time.Second)

	t.Logf("Exit error: %v", exitErr)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}
