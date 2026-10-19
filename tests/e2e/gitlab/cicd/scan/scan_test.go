//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGLCicdScan_HappyPath(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-project", "path_with_namespace": "group/test-project", "web_url": "https://gitlab.example/group/test-project"},
			})

		case "/api/v4/projects/1/ci/lint":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"valid": true,
				"merged_yaml": "deploy:\n  script:\n    - echo GITLAB_USER_ID=19357\n",
				"warnings": [],
				"errors": []
			}`))

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "cicd", "scan",
		"--url", server.URL,
		"--token", "glpat-test-token-123",
		"--secrets-verification=false",
		"--confidence=medium",
		"--json",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed")
	assert.Contains(t, stdout, "GITLAB_USER_ID=19357", "Should detect the indicator embedded in the CI/CD YAML")
	assert.Contains(t, stdout, `"type":"cicd-yaml"`)
	assert.Contains(t, stdout, `"url":"https://gitlab.example/group/test-project/-/blob/HEAD/.gitlab-ci.yml"`)
	assert.NotContains(t, stdout, `"type":"log"`)

	requests := getRequests()
	for _, req := range requests {
		assert.NotContains(t, req.Path, "/jobs", "Should never fetch job logs or artifacts")
		assert.NotContains(t, req.Path, "/pipelines", "Should never list pipelines")
	}

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

func TestGLCicdScan_RepoFlag(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects/group/project", "/api/v4/projects/group%2Fproject":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 1, "name": "project", "path_with_namespace": "group/project",
			})

		case "/api/v4/projects/1/ci/lint":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"valid": true, "merged_yaml": "job:\n  script: echo hi\n", "warnings": [], "errors": []}`))

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, _, exitErr := testutil.RunCLI(t, []string{
		"gl", "cicd", "scan",
		"--url", server.URL,
		"--token", "glpat-test",
		"--repo", "group/project",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with --repo flag")

	requests := getRequests()
	lintRequestFound := false
	for _, req := range requests {
		if req.Path == "/api/v4/projects/1/ci/lint" {
			lintRequestFound = true
		}
	}
	assert.True(t, lintRequestFound, "Should fetch the merged CI/CD YAML for the targeted repository")
	t.Logf("STDOUT:\n%s", stdout)
}

func TestGLCicdScan_MissingRequiredFlags(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "cicd", "scan",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without url/token")
	output := stdout + stderr
	assert.Contains(t, output, "gitlab.url", "Should mention missing required url config key")
}
