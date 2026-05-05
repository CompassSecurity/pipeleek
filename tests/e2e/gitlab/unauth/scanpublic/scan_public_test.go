//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGLunaScanPublic_UsesPipelineJobsAndRawTrace(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/gitlab/api/v4/projects/group%2Fproject", "/gitlab/api/v4/projects/group/project":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":                  1,
				"name":                "project",
				"path_with_namespace": "group/project",
			})

		case "/gitlab/api/v4/projects/1/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":     100,
				"status": "success",
			}})

		case "/gitlab/api/v4/projects/1/pipelines/100/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":     1000,
				"name":   "lint",
				"status": "success",
			}})

		case "/gitlab/group/project/-/jobs/1000/raw":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("plain job log\nno secrets here\n"))

		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "scan-public",
		"--gitlab", server.URL + "/gitlab",
		"--repo", "group/project",
		"--job-limit", "1",
	}, nil, 15*time.Second)

	require.NoError(t, exitErr)

	requests := getRequests()
	paths := make([]string, 0, len(requests))
	for _, req := range requests {
		paths = append(paths, req.Path)
	}

	assert.True(t,
		containsPath(paths, "/gitlab/api/v4/projects/group%2Fproject") || containsPath(paths, "/gitlab/api/v4/projects/group/project"),
		"expected project lookup request to be recorded",
	)
	assert.Contains(t, paths, "/gitlab/api/v4/projects/1/pipelines")
	assert.Contains(t, paths, "/gitlab/api/v4/projects/1/pipelines/100/jobs")
	assert.Contains(t, paths, "/gitlab/group/project/-/jobs/1000/raw")
	assert.NotContains(t, paths, "/gitlab/help")
	assert.NotContains(t, paths, "/gitlab/api/v4/projects/1/jobs/1000/trace")

	combinedOutput := stdout + stderr
	assert.True(t, strings.Contains(combinedOutput, "Running in unauthenticated mode") || strings.Contains(combinedOutput, "Done scanning repository"))
	assert.NotContains(t, combinedOutput, "Gitlab Version Check")
	assert.NotContains(t, combinedOutput, "Failed determining GitLab version via Website")
	assert.NotContains(t, combinedOutput, "Job trace is not publicly accessible")
	assert.NotContains(t, combinedOutput, "Job trace not accessible via web URL")
	assert.NotContains(t, combinedOutput, "Failed fetching job trace")
	assert.NotContains(t, combinedOutput, "Failed listing public pipelines")
	assert.NotContains(t, combinedOutput, "Unexpected status while listing public pipelines")
	assert.NotContains(t, combinedOutput, "Unexpected status while listing public pipeline jobs")
	assert.NotContains(t, combinedOutput, "Pipelines not publicly accessible")
	assert.NotContains(t, combinedOutput, "error")
	assert.NotContains(t, combinedOutput, "Error")
	assert.NotContains(t, combinedOutput, "panic")
	assert.NotContains(t, combinedOutput, "fatal")
	assert.NotContains(t, combinedOutput, "warning")
	assert.NotContains(t, combinedOutput, "warn")
	assert.NotContains(t, combinedOutput, "403")
	assert.NotContains(t, combinedOutput, "401")
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

func containsPath(paths []string, expected string) bool {
	for _, path := range paths {
		if path == expected {
			return true
		}
	}

	return false
}
