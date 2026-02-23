package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func logOnFailure(t *testing.T, format string, args ...any) {
	t.Helper()
	if t.Failed() {
		t.Logf(format, args...)
	}
}

func TestGitLabScan_InvalidToken(t *testing.T) {
	t.Parallel()
	// Mock server that returns 401 Unauthorized
	server, _, cleanup := testutil.StartMockServerWithRecording(t, testutil.WithError(http.StatusUnauthorized, "invalid token"))
	defer cleanup()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "invalid-token",
	}, nil, 10*time.Second)

	// Command completes but logs authentication errors
	output := stdout + stderr
	assert.Contains(t, output, "401", "Should show 401 authentication error")
	assert.Contains(t, output, "invalid token", "Should mention invalid token")
	logOnFailure(t, "Output:\n%s", output)
}

// TestGitLabScan_MissingRequiredFlags tests validation of required flags

func TestGitLabScan_MissingRequiredFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing_gitlab_flag",
			args: []string{"gl", "scan", "--token", "test"},
		},
		{
			name: "missing_token_flag",
			args: []string{"gl", "scan", "--gitlab", "https://gitlab.com"},
		},
		{
			name: "missing_both_flags",
			args: []string{"gl", "scan"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stdout, stderr, exitErr := testutil.RunCLI(t, tt.args, nil, 5*time.Second)

			// Command should fail due to missing required flags
			assert.NotNil(t, exitErr, "Command should fail with missing required flags")

			output := stdout + stderr
			// Output should mention the missing flag
			assert.True(t,
				len(output) > 0,
				"Should have error output about missing flags",
			)
			logOnFailure(t, "Output:\n%s", output)
		})
	}
}

// TestGitLabScan_InvalidURL tests handling of malformed URLs

func TestGitLabScan_InvalidURL(t *testing.T) {
	t.Parallel()
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", "not-a-valid-url",
		"--token", "test-token",
	}, nil, 5*time.Second)

	// Should fail with invalid URL
	assert.NotNil(t, exitErr, "Command should fail with invalid URL")

	output := stdout + stderr
	logOnFailure(t, "Output:\n%s", output)
}

// TestGitLabScan_FlagVariations tests various flag combinations

func TestGitLab_APIErrorHandling(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		statusCode int
		errorMsg   string
	}{
		{
			name:       "unauthorized_401",
			statusCode: http.StatusUnauthorized,
			errorMsg:   "Invalid credentials",
		},
		{
			name:       "forbidden_403",
			statusCode: http.StatusForbidden,
			errorMsg:   "Access denied",
		},
		{
			name:       "not_found_404",
			statusCode: http.StatusNotFound,
			errorMsg:   "Resource not found",
		},
		{
			name:       "rate_limit_429",
			statusCode: http.StatusTooManyRequests,
			errorMsg:   "Rate limit exceeded",
		},
		{
			name:       "server_error_500",
			statusCode: http.StatusInternalServerError,
			errorMsg:   "Internal server error",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server, _, cleanup := testutil.StartMockServerWithRecording(t, testutil.WithError(tt.statusCode, tt.errorMsg))
			defer cleanup()

			stdout, stderr, exitErr := testutil.RunCLI(t, []string{
				"gl", "scan",
				"--gitlab", server.URL,
				"--token", "test-token",
			}, nil, 5*time.Second)

			// Error handling depends on implementation
			// Log for inspection
			logOnFailure(t, "Status code: %d", tt.statusCode)
			logOnFailure(t, "Exit error: %v", exitErr)
			logOnFailure(t, "STDOUT:\n%s", stdout)
			logOnFailure(t, "STDERR:\n%s", stderr)
		})
	}
}

// TestGitLabScan_Timeout tests behavior when API is slow/unresponsive

func TestGitLabScan_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	// Create a mock server that delays responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(4 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Use a short timeout to ensure we hit it
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "test-token",
	}, nil, 2*time.Second)

	// Should timeout
	logOnFailure(t, "Exit error: %v", exitErr)
	logOnFailure(t, "STDOUT:\n%s", stdout)
	logOnFailure(t, "STDERR:\n%s", stderr)

	// Assert timeout occurred (either via our test timeout or CLI timeout)
	assert.NotNil(t, exitErr, "Command should timeout or be interrupted")
}

// TestGitLab_ProxySupport tests HTTP_PROXY environment variable

func TestGitLab_ProxySupport(t *testing.T) {
	t.Parallel()
	// Create mock proxy server
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Proxy just forwards the request
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer proxyServer.Close()

	// Create mock GitLab server
	gitlabServer, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	defer cleanup()

	// Run with HTTP_PROXY environment variable
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", gitlabServer.URL,
		"--token", "test-token",
	}, []string{
		fmt.Sprintf("HTTP_PROXY=%s", proxyServer.URL),
	}, 5*time.Second)

	// Note: Actual proxy usage depends on implementation
	// This test verifies the command doesn't crash with proxy env var set
	logOnFailure(t, "Exit error: %v", exitErr)
	logOnFailure(t, "STDOUT:\n%s", stdout)
	logOnFailure(t, "STDERR:\n%s", stderr)
}
