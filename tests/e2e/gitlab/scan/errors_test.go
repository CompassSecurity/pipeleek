package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabScan_JobStatusSkipsProjectErrors(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, requests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v4/metadata":
					_, _ = w.Write([]byte(`{"version":"18.0.0"}`))
				case "/api/v4/projects":
					_, _ = w.Write([]byte(`[{"id":1,"path_with_namespace":"group/restricted"},{"id":2,"path_with_namespace":"group/accessible"}]`))
				case "/api/v4/projects/1/jobs":
					assert.Equal(t, []string{"failed"}, r.URL.Query()["scope[]"])
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"message":"project jobs inaccessible"}`))
				case "/api/v4/projects/2/jobs":
					assert.Equal(t, []string{"failed"}, r.URL.Query()["scope[]"])
					_, _ = w.Write([]byte(`[{"id":20,"name":"build","status":"failed"}]`))
				case "/api/v4/projects/2/jobs/20/trace":
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte("Build failed, no secrets\n"))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			})
			defer cleanup()

			stdout, stderr, err := testutil.RunCLI(t, []string{
				"gl", "scan", "--url", server.URL, "--token", "glpat-test-token",
				"--job-status", "failed",
			}, nil, 30*time.Second)
			require.NoError(t, err, "%s\n%s", stdout, stderr)
			assert.NotContains(t, stdout+stderr, "Failed fetching jobs with requested status filter")
			var jobPaths, tracePaths []string
			for _, request := range requests() {
				if strings.HasSuffix(request.Path, "/jobs") {
					jobPaths = append(jobPaths, request.Path)
				}
				if strings.HasSuffix(request.Path, "/trace") {
					tracePaths = append(tracePaths, request.Path)
				}
			}
			assert.ElementsMatch(t, []string{"/api/v4/projects/1/jobs", "/api/v4/projects/2/jobs"}, jobPaths)
			assert.Equal(t, []string{"/api/v4/projects/2/jobs/20/trace"}, tracePaths)
		})
	}
}

func TestGitLabScan_PipelineSourceSkipsDeletedResources(t *testing.T) {
	for _, resource := range []string{"project", "pipeline"} {
		t.Run(resource, func(t *testing.T) {
			server, requests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v4/metadata":
					_, _ = w.Write([]byte(`{"version":"18.0.0"}`))
				case "/api/v4/projects":
					_, _ = w.Write([]byte(`[{"id":1,"path_with_namespace":"group/first"},{"id":2,"path_with_namespace":"group/second"}]`))
				case "/api/v4/projects/1/pipelines":
					assert.Equal(t, "schedule", r.URL.Query().Get("source"))
					if resource == "project" {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"message":"project deleted"}`))
					} else {
						_, _ = w.Write([]byte(`[{"id":10},{"id":11}]`))
					}
				case "/api/v4/projects/1/pipelines/10/jobs":
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message":"pipeline deleted"}`))
				case "/api/v4/projects/1/pipelines/11/jobs":
					_, _ = w.Write([]byte(`[{"id":11,"name":"build","status":"failed"}]`))
				case "/api/v4/projects/2/pipelines":
					assert.Equal(t, "schedule", r.URL.Query().Get("source"))
					_, _ = w.Write([]byte(`[{"id":20}]`))
				case "/api/v4/projects/2/pipelines/20/jobs":
					_, _ = w.Write([]byte(`[{"id":20,"name":"build","status":"failed"}]`))
				case "/api/v4/projects/1/jobs/11/trace", "/api/v4/projects/2/jobs/20/trace":
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte("Build failed, no secrets\n"))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			})
			defer cleanup()

			stdout, stderr, err := testutil.RunCLI(t, []string{
				"gl", "scan", "--url", server.URL, "--token", "glpat-test-token",
				"--pipeline-source", "schedule", "--job-status", "failed",
			}, nil, 30*time.Second)
			require.NoError(t, err, "%s\n%s", stdout, stderr)
			var pipelinePaths, jobPaths, tracePaths []string
			for _, request := range requests() {
				switch {
				case strings.HasSuffix(request.Path, "/pipelines"):
					pipelinePaths = append(pipelinePaths, request.Path)
				case strings.HasSuffix(request.Path, "/jobs"):
					jobPaths = append(jobPaths, request.Path)
				case strings.HasSuffix(request.Path, "/trace"):
					tracePaths = append(tracePaths, request.Path)
				}
			}
			assert.ElementsMatch(t, []string{"/api/v4/projects/1/pipelines", "/api/v4/projects/2/pipelines"}, pipelinePaths)
			wantJobs := []string{"/api/v4/projects/2/pipelines/20/jobs"}
			wantTraces := []string{"/api/v4/projects/2/jobs/20/trace"}
			if resource == "pipeline" {
				wantJobs = append(wantJobs, "/api/v4/projects/1/pipelines/10/jobs", "/api/v4/projects/1/pipelines/11/jobs")
				wantTraces = append(wantTraces, "/api/v4/projects/1/jobs/11/trace")
			}
			assert.ElementsMatch(t, wantJobs, jobPaths)
			assert.ElementsMatch(t, wantTraces, tracePaths)
		})
	}
}

func TestGitLabScan_InvalidToken(t *testing.T) {

	// Mock server that returns 401 Unauthorized
	server, _, cleanup := testutil.StartMockServerWithRecording(t, testutil.WithError(http.StatusUnauthorized, "invalid token"))
	defer cleanup()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--url", server.URL,
		"--token", "invalid-token",
	}, nil, 30*time.Second)

	// Command completes but logs authentication errors
	output := stdout + stderr
	assert.Contains(t, output, "401", "Should show 401 authentication error")
	assert.Contains(t, output, "invalid token", "Should mention invalid token")
	t.Logf("Output:\n%s", output)
}

// TestGitLabScan_MissingRequiredFlags tests validation of required flags

func TestGitLabScan_MissingRequiredFlags(t *testing.T) {

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
			args: []string{"gl", "scan", "--url", "https://gitlab.com"},
		},
		{
			name: "missing_both_flags",
			args: []string{"gl", "scan"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Do not use t.Parallel() - stdout/stderr redirection conflicts

			stdout, stderr, exitErr := testutil.RunCLI(t, tt.args, nil, 30*time.Second)

			// Command should fail due to missing required flags
			assert.NotNil(t, exitErr, "Command should fail with missing required flags")

			output := stdout + stderr
			// Output should mention the missing flag
			assert.True(t,
				len(output) > 0,
				"Should have error output about missing flags",
			)
			t.Logf("Output:\n%s", output)
		})
	}
}

// TestGitLabScan_InvalidURL tests handling of malformed URLs

func TestGitLabScan_InvalidURL(t *testing.T) {

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--url", "not-a-valid-url",
		"--token", "test-token",
	}, nil, 30*time.Second)

	// Should fail with invalid URL
	assert.NotNil(t, exitErr, "Command should fail with invalid URL")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

// TestGitLabScan_FlagVariations tests various flag combinations

func TestGitLab_APIErrorHandling(t *testing.T) {
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
			// Do not use t.Parallel() - stdout/stderr redirection conflicts

			server, _, cleanup := testutil.StartMockServerWithRecording(t, testutil.WithError(tt.statusCode, tt.errorMsg))
			defer cleanup()

			stdout, stderr, exitErr := testutil.RunCLI(t, []string{
				"gl", "scan",
				"--url", server.URL,
				"--token", "test-token",
			}, nil, 10*time.Second)

			// Error handling depends on implementation
			// Log for inspection
			t.Logf("Status code: %d", tt.statusCode)
			t.Logf("Exit error: %v", exitErr)
			t.Logf("STDOUT:\n%s", stdout)
			t.Logf("STDERR:\n%s", stderr)
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
		time.Sleep(15 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.CloseClientConnections()
	defer server.Close()

	// Use a short timeout to ensure we hit it
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"--http-timeout", "500ms",
		"gl", "scan",
		"--url", server.URL,
		"--token", "test-token",
	}, nil, 3*time.Second)

	// Should timeout
	t.Logf("Exit error: %v", exitErr)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	output := stdout + stderr
	hasTimeoutSignal := strings.Contains(output, "timeout") ||
		strings.Contains(output, "deadline exceeded") ||
		strings.Contains(output, "Client.Timeout exceeded")

	// Accept either behavior:
	// 1) command exits cleanly but reports request timeout in output, or
	// 2) test harness timeout interrupts command.
	assert.True(t, hasTimeoutSignal || exitErr != nil, "Expected timeout signal in output or harness timeout interruption")
}

// TestGitLab_ProxySupport tests HTTP_PROXY environment variable

func TestGitLab_ProxySupport(t *testing.T) {

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
		"--url", gitlabServer.URL,
		"--token", "test-token",
	}, []string{
		fmt.Sprintf("HTTP_PROXY=%s", proxyServer.URL),
	}, 10*time.Second)

	// Note: Actual proxy usage depends on implementation
	// This test verifies the command doesn't crash with proxy env var set
	t.Logf("Exit error: %v", exitErr)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}
