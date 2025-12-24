//go:build e2e

package e2e

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func setupMockGitLabCicdAPI(t *testing.T) string {
	mux := http.NewServeMux()

	// Project endpoint with CI/CD configuration
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":123,"name":"test-project","web_url":"https://gitlab.com/test-project"}`))
	})

	// CI lint endpoint
	mux.HandleFunc("/api/v4/projects/123/ci/lint", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"valid": true,
			"merged_yaml": "stages:\n  - test\n\ntest-job:\n  stage: test\n  script:\n    - echo 'Testing'",
			"warnings": [],
			"errors": []
		}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGLCicdYaml(t *testing.T) {
	apiURL := setupMockGitLabCicdAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "cicd", "yaml",
		"--gitlab", apiURL,
		"--token", "mock-token",
		"--project", "test-project",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "CI/CD yaml command should succeed")
	assert.Contains(t, stdout, "test-job", "Should contain job name from YAML")
	assert.Contains(t, stdout, "Done, Bye Bye", "Should show completion message")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLCicdYaml_MissingProject(t *testing.T) {
	apiURL := setupMockGitLabCicdAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "cicd", "yaml",
		"--gitlab", apiURL,
		"--token", "mock-token",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without project flag")
	output := stdout + stderr
	assert.Contains(t, output, "Project name is required", "Should mention missing required project")
}

func TestGLCicdYaml_InvalidProject(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"404 Project Not Found"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "cicd", "yaml",
		"--gitlab", server.URL,
		"--token", "mock-token",
		"--project", "nonexistent/project",
	}, nil, 10*time.Second)

	// Should report a not found error and exit non-zero
	combined := stdout + stderr
	assert.NotNil(t, exitErr, "Should fail for invalid project")
	assert.Contains(t, combined, "Failed fetching project", "Should log fetch failure")
	assert.Contains(t, combined, "404", "Should include not found indicator")
}

func TestGLCicdYaml_NoCiCdYaml(t *testing.T) {
	mux := http.NewServeMux()

	// Project exists
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":123,"name":"test-project","web_url":"https://gitlab.com/test-project"}`))
	})

	// CI lint endpoint returns error when no .gitlab-ci.yml exists
	mux.HandleFunc("/api/v4/projects/123/ci/lint", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"valid": false,
			"merged_yaml": "",
			"warnings": [],
			"errors": ["Please provide content of .gitlab-ci.yml"]
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "cicd", "yaml",
		"--gitlab", server.URL,
		"--token", "mock-token",
		"--project", "test-project",
	}, nil, 10*time.Second)

	// Should report an error indicating no CI/CD yaml file exists
	combined := stdout + stderr
	assert.NotNil(t, exitErr, "Should fail when project has no CI/CD configuration")
	assert.Contains(t, combined, "most certainly not have a .gitlab-ci.yml file", "Should indicate missing CI/CD yaml file")
}
