package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGiteaScan_InvalidURL(t *testing.T) {
	t.Parallel()
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", "not-a-valid-url",
		"--token", "gitea-token",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail with invalid URL")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

// TestGiteaScan_MissingToken tests missing required token flag

func TestGiteaScan_MissingToken(t *testing.T) {
	t.Parallel()
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", "https://gitea.example.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without --token flag")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

// TestGiteaScan_Threads tests thread count configuration

func TestGitea_APIErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		statusCode int
		message    string
	}{
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			message:    "Invalid token",
		},
		{
			name:       "forbidden",
			statusCode: http.StatusForbidden,
			message:    "Access forbidden",
		},
		{
			name:       "not_found",
			statusCode: http.StatusNotFound,
			message:    "Resource not found",
		},
		{
			name:       "server_error",
			statusCode: http.StatusInternalServerError,
			message:    "Internal server error",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server, _, cleanup := testutil.StartMockServerWithRecording(t, testutil.WithError(tt.statusCode, tt.message))
			defer cleanup()

			stdout, stderr, exitErr := testutil.RunCLI(t, []string{
				"gitea", "scan",
				"--gitea", server.URL,
				"--token", "test-token",
			}, nil, 10*time.Second)

			t.Logf("Status code: %d", tt.statusCode)
			t.Logf("Exit error: %v", exitErr)
			t.Logf("STDOUT:\n%s", stdout)
			t.Logf("STDERR:\n%s", stderr)
		})
	}
}

// TestGitea_TruffleHogVerification tests credential verification flag
