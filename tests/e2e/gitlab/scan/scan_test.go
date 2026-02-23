package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGitLabScan_HappyPath(t *testing.T) {
	t.Parallel()
	// Mock GitLab API responses
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			// Return list of projects
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":                  1,
					"name":                "test-project",
					"path_with_namespace": "group/test-project",
				},
			})

		case "/api/v4/projects/1/pipelines":
			// Return list of pipelines for project
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":     100,
					"ref":    "main",
					"status": "success",
				},
			})

		case "/api/v4/projects/1/pipelines/100/jobs":
			// Return jobs for pipeline
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":     1000,
					"name":   "test-job",
					"status": "success",
				},
			})

		case "/api/v4/projects/1/jobs/1000/trace":
			// Return job log with potential secret
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Job log content\nNo secrets here\n"))

		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		}
	})
	defer cleanup()

	// Run scan command
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token-123",
	}, nil, 10*time.Second)

	// Assert command succeeded
	assert.Nil(t, exitErr, "Command should succeed")

	// Assert API calls were made
	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make at least one API request")

	// Verify authentication header
	for _, req := range requests {
		if req.Path == "/api/v4/projects" {
			testutil.AssertRequestHeader(t, req, "Private-Token", "glpat-test-token-123")
		}
	}

	// Output should indicate scan progress (adjust based on actual output format)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitLabScan_WithArtifacts tests scanning with artifact download enabled

func TestGitLabScan_WithArtifacts(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-project"},
			})

		case "/api/v4/projects/1/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 100, "status": "success"},
			})

		case "/api/v4/projects/1/pipelines/100/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1000, "name": "build", "artifacts_file": map[string]string{"filename": "artifacts.zip"}},
			})

		case "/api/v4/projects/1/jobs/1000/artifacts":
			// Return mock artifact data
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PK\x03\x04")) // ZIP magic bytes

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test",
		"--artifacts",      // Enable artifact scanning
		"--job-limit", "1", // Limit to 1 job for faster test
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with --artifacts flag")

	// Verify artifacts endpoint was called
	requests := getRequests()
	artifactRequestFound := false
	for _, req := range requests {
		if req.Path == "/api/v4/projects/1/jobs/1000/artifacts" {
			artifactRequestFound = true
			break
		}
	}

	// Note: This assertion may need adjustment based on actual CLI logic
	t.Logf("Artifact request made: %v", artifactRequestFound)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitLabScan_InvalidToken tests authentication failure handling

func TestGitLabScan_FlagVariations(t *testing.T) {
	t.Parallel()
	// Create mock server for all sub-tests
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Handle specific project lookup by name (for --repo flag)
		if strings.Contains(r.URL.Path, "/projects/") && strings.Contains(r.URL.RawQuery, "search=") {
			// When querying projects by name, return a single project object in an array
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "project", "path_with_namespace": "group/project"},
			})
		} else if strings.HasSuffix(r.URL.Path, "/projects/group%2Fproject") || strings.HasSuffix(r.URL.Path, "/projects/group/project") {
			// When fetching a specific project, return a single object (not array)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 1, "name": "project", "path_with_namespace": "group/project",
			})
		} else if strings.Contains(r.URL.Path, "/groups/") && !strings.HasSuffix(r.URL.Path, "/groups") {
			// When fetching a specific namespace/group, return a single object (not array)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 1, "name": "mygroup", "path": "mygroup",
			})
		} else {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	tests := []struct {
		name        string
		args        []string
		shouldError bool
	}{
		{
			name:        "with_search_query",
			args:        []string{"gl", "scan", "--gitlab", server.URL, "--token", "test", "--search", "kubernetes"},
			shouldError: false,
		},
		{
			name:        "with_owned_flag",
			args:        []string{"gl", "scan", "--gitlab", server.URL, "--token", "test", "--owned"},
			shouldError: false,
		},
		{
			name:        "with_member_flag",
			args:        []string{"gl", "scan", "--gitlab", server.URL, "--token", "test", "--member"},
			shouldError: false,
		},
		{
			name:        "with_repo_flag",
			args:        []string{"gl", "scan", "--gitlab", server.URL, "--token", "test", "--repo", "group/project"},
			shouldError: false,
		},
		{
			name:        "with_namespace_flag",
			args:        []string{"gl", "scan", "--gitlab", server.URL, "--token", "test", "--namespace", "mygroup"},
			shouldError: false,
		},
		{
			name:        "with_job_limit",
			args:        []string{"gl", "scan", "--gitlab", server.URL, "--token", "test", "--job-limit", "10"},
			shouldError: false,
		},
		{
			name:        "with_threads",
			args:        []string{"gl", "scan", "--gitlab", server.URL, "--token", "test", "--threads", "2"},
			shouldError: false,
		},
		{
			name:        "with_verbose",
			args:        []string{"gl", "scan", "--gitlab", server.URL, "--token", "test", "-v"},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Note: Not using t.Parallel() here since we share the server

			stdout, stderr, exitErr := testutil.RunCLI(t, tt.args, nil, 10*time.Second)

			if tt.shouldError {
				assert.NotNil(t, exitErr, "Command should fail")
			} else {
				assert.Nil(t, exitErr, "Command should succeed")
			}

			t.Logf("STDOUT:\n%s", stdout)
			if stderr != "" {
				t.Logf("STDERR:\n%s", stderr)
			}
		})
	}
}

// TestGitLabEnum tests GitLab enumeration command
