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

func setupMockGitLabRunnersAPI(t *testing.T) string {
	mux := http.NewServeMux()

	// Projects list and creation endpoint
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":999,"name":"pipeleek-runner-test","web_url":"https://gitlab.com/pipeleek-runner-test"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":123,"name":"test-project"}]`))
	})

	// Repository files endpoint for creating .gitlab-ci.yml
	mux.HandleFunc("/api/v4/projects/999/repository/files/.gitlab-ci.yml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"file_path":".gitlab-ci.yml","branch":"main"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// Project runners endpoint
	mux.HandleFunc("/api/v4/projects/123/runners", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{
				"id":1,
				"description":"docker-runner",
				"active":true,
				"is_shared":false,
				"tag_list":["docker","linux"]
			},
			{
				"id":2,
				"description":"shell-runner",
				"active":true,
				"is_shared":true,
				"tag_list":["shell","macos"]
			}
		]`))
	})

	// Groups list endpoint
	mux.HandleFunc("/api/v4/groups", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"id":456,"name":"test-group","web_url":"https://gitlab.com/test-group"}
		]`))
	})

	// Group runners endpoint
	mux.HandleFunc("/api/v4/groups/456/runners", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{
				"id":3,
				"description":"group-runner",
				"active":true,
				"is_shared":false,
				"tag_list":["kubernetes"]
			}
		]`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGLRunnersList(t *testing.T) {
	apiURL := setupMockGitLabRunnersAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "runners", "list",
		"--gitlab", apiURL,
		"--token", "mock-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Runners list command should succeed")
	assert.Contains(t, stdout, "Done, Bye Bye", "Should show completion message")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRunnersList_MissingToken(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "runners", "list",
		"--gitlab", "https://gitlab.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token")
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing", "Should mention missing required configuration")
}

func TestGLRunnersExploit_DryRun(t *testing.T) {
	apiURL := setupMockGitLabRunnersAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "runners", "exploit",
		"--gitlab", apiURL,
		"--token", "mock-token",
		"--tags", "docker,shell",
		"--dry=true",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Runners exploit dry run should succeed")
	assert.Contains(t, stdout, ".gitlab-ci.yml", "Should show CI/CD YAML output")
	assert.Contains(t, stdout, "docker", "Should include docker tag in YAML")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRunnersExploit_DryRun_WithoutTokenAndGitlab(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "runners", "exploit",
		"--dry=true",
		"--tags", "docker,shell",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Runners exploit dry run should succeed without token and gitlab flags")
	assert.Contains(t, stdout, ".gitlab-ci.yml", "Should show CI/CD YAML output")
	assert.Contains(t, stdout, "docker", "Should include docker tag in YAML")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRunnersExploit_NonDryRun_WithoutTokenAndGitlab(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "runners", "exploit",
		"--dry=false",
	}, nil, 10*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token and gitlab flags when not in dry-run mode")
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing", "Should mention missing required configuration")
	assert.Contains(t, output, "gitlab.url", "Should mention gitlab.url is missing")
	assert.Contains(t, output, "gitlab.token", "Should mention gitlab.token is missing")
}


func TestGLRunnersExploit_WithRepoCreation(t *testing.T) {
	apiURL := setupMockGitLabRunnersAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "runners", "exploit",
		"--gitlab", apiURL,
		"--token", "mock-token",
		"--tags", "docker",
		"--repo-name", "test-exploit-repo",
		"--dry=false",
		"--shell=false",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Runners exploit should succeed")
	assert.Contains(t, stdout, "Done, Bye Bye", "Should show completion message")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRunnersExploit_Unauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"401 Unauthorized"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "runners", "exploit",
		"--gitlab", server.URL,
		"--token", "invalid-token",
		"--dry=false",
	}, nil, 10*time.Second)

	// Should fail with unauthorized error when creating project
	assert.NotNil(t, exitErr, "Should fail with unauthorized error")
	output := stdout + stderr
	assert.Contains(t, output, "401", "Should mention 401 error")
}
