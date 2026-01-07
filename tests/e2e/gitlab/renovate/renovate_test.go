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

func setupMockGitLabRenovateAPI(t *testing.T) string {
	mux := http.NewServeMux()
	// Generic project GET handler to support numeric id or path-based project lookups
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// return a generic project object for any project identifier
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":123,"name":"test-repo","name_with_namespace":"group/test-repo","web_url":"https://gitlab.com/test-repo","default_branch":"main","access_levels":{"project_access_level":40,"group_access_level":0},"permissions":{"project_access":{"access_level":40},"group_access":{"access_level":0}}}`))
			return
		}
		// fallback
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// list projects
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"id":123,"name":"test-repo","web_url":"https://gitlab.com/test-repo"}]`))
			return
		}
		// create project
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":123,"name":"test-repo","web_url":"https://gitlab.com/test-repo"}`))
	})
	mux.HandleFunc("/api/v4/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":456,"username":"test-user"}]`))
	})
	mux.HandleFunc("/api/v4/projects/123", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":123,"name":"test-repo","web_url":"https://gitlab.com/test-repo"}`))
	})
	mux.HandleFunc("/api/v4/projects/123/members", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":456,"access_level":40}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":456,"access_level":40}]`))
	})

	// emulate branch creation: first call returns existing main branch, subsequent calls include the renovate branch
	branchCalls := 0
	mux.HandleFunc("/api/v4/projects/123/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		branchCalls++
		w.WriteHeader(http.StatusOK)
		if branchCalls == 1 {
			w.Write([]byte(`[{"name":"main"}]`))
			return
		}
		w.Write([]byte(`[{"name":"main"},{"name":"renovate/test-branch"}]`))
	})
	mux.HandleFunc("/api/v4/projects/123/pipeline", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":789,"status":"success"}`))
	})

	// handle repository files create/update
	mux.HandleFunc("/api/v4/projects/123/repository/files/", func(w http.ResponseWriter, r *http.Request) {
		// any file create/update should return success
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"file_path":"renovate.json","branch":"main","commit_id":"abc123"}`))
			return
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"file_path":"renovate.json","branch":"main","commit_id":"def456"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"file_path":"renovate.json"}`))
	})

	// raw file retrieval for .gitlab-ci.yml
	mux.HandleFunc("/api/v4/projects/123/repository/files/.gitlab-ci.yml/raw", func(w http.ResponseWriter, r *http.Request) {
		// return a minimal CI/CD YAML
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test-job:\n  script:\n    - echo hello"))
	})

	// CI lint endpoint to provide merged_yaml (used by FetchCICDYml)
	mux.HandleFunc("/api/v4/projects/123/ci/lint", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"valid": true, "merged_yaml": "test-job:\n  script:\n    - echo hello", "warnings": []}`))
	})

	// protected branches lookup for default branch protections
	mux.HandleFunc("/api/v4/projects/123/protected_branches/main", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"main","push_access_levels":[{"access_level":50}],"merge_access_levels":[{"access_level":50}]}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGLRenovateEnum(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "enum",
		"--gitlab", apiURL,
		"--token", "mock-token",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	assert.Contains(t, stdout, "Fetched all projects")
	assert.NotContains(t, stderr, "error")
}

func TestGLRenovateAutodiscovery(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "autodiscovery",
		"--gitlab", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-repo",
		"--username", "test-user",
		"-v",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery command should succeed")
	assert.Contains(t, stdout, "Created project")
	assert.Contains(t, stdout, "Created file", "Should log file creation in verbose mode")
	assert.Contains(t, stdout, "Inviting user")
	assert.Contains(t, stdout, "Gradle wrapper", "Should mention Gradle wrapper mechanism")
	assert.Contains(t, stdout, "gradlew", "Should mention gradlew script")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRenovateAutodiscoveryWithCICD(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "autodiscovery",
		"--gitlab", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-repo-cicd",
		"--username", "test-user",
		"--add-renovate-cicd-for-debugging",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery with CICD flag should succeed")
	assert.Contains(t, stdout, "Created project")
	assert.Contains(t, stdout, "Created .gitlab-ci.yml")
	assert.Contains(t, stdout, "RENOVATE_TOKEN", "Should mention token setup")
	assert.Contains(t, stdout, "api", "Should mention api scope requirement")
	assert.Contains(t, stdout, "maintainer", "Should mention maintainer role requirement")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRenovateAutodiscoveryWithoutUsername(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "autodiscovery",
		"--gitlab", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-repo-no-user",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery without username should succeed")
	assert.Contains(t, stdout, "Created project")
	assert.Contains(t, stdout, "No username provided")
	assert.Contains(t, stdout, "invite the victim Renovate Bot user manually")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRenovatePrivesc(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "privesc",
		"--gitlab", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-repo",
		"--renovate-branches-regex", "renovate/.*",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Privesc command should succeed")
	assert.Contains(t, stdout, "Ensure the Renovate bot")
	assert.Contains(t, stdout, "renovate/test-branch")
	assert.NotContains(t, stderr, "fatal")
}
func TestGLRenovatePrivescWithMonitoringInterval(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "privesc",
		"--gitlab", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-repo",
		"--renovate-branches-regex", "renovate/.*",
		"--monitoring-interval", "500ms",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Privesc command with monitoring-interval should succeed")
	assert.Contains(t, stdout, "Ensure the Renovate bot")
	assert.Contains(t, stdout, "renovate/test-branch")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRenovatePrivescWithInvalidMonitoringInterval(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	_, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "privesc",
		"--gitlab", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-repo",
		"--renovate-branches-regex", "renovate/.*",
		"--monitoring-interval", "invalid-duration",
	}, nil, 10*time.Second)
	assert.NotNil(t, exitErr, "Privesc command with invalid monitoring-interval should fail")
	assert.Contains(t, stderr, "Failed to parse monitoring-interval duration")
}