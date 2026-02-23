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

// TestGitHubScan_SingleRepository_Success tests scanning a single repository with --repo flag
func TestGitHubScan_SingleRepository_Success(t *testing.T) {
	t.Parallel()
	repoOwner := "test-org"
	repoName := "test-repo"
	repoFullName := repoOwner + "/" + repoName

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (SingleRepo): %s %s", r.Method, r.URL.Path)

		switch {
		case r.URL.Path == "/api/v3/repos/"+repoOwner+"/"+repoName:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":        12345,
				"name":      repoName,
				"full_name": repoFullName,
				"html_url":  "https://github.com/" + repoFullName,
				"owner": map[string]interface{}{
					"login": repoOwner,
				},
			})

		case r.URL.Path == "/api/v3/repos/"+repoOwner+"/"+repoName+"/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{
						"id":            1001,
						"name":          "CI Build",
						"display_title": "Test workflow run",
						"html_url":      "https://github.com/" + repoFullName + "/actions/runs/1001",
						"status":        "completed",
					},
				},
				"total_count": 1,
			})

		case strings.Contains(r.URL.Path, "/actions/runs/1001/logs"):
			w.WriteHeader(http.StatusGone)

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "scan",
		"--github", server.URL,
		"--token", "ghp_test_token",
		"--repo", repoFullName,
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Single repo scan should succeed")

	requests := getRequests()
	var repoGetRequests []testutil.RecordedRequest
	var workflowRunRequests []testutil.RecordedRequest

	for _, req := range requests {
		if req.Path == "/api/v3/repos/"+repoOwner+"/"+repoName {
			repoGetRequests = append(repoGetRequests, req)
		}
		if req.Path == "/api/v3/repos/"+repoOwner+"/"+repoName+"/actions/runs" {
			workflowRunRequests = append(workflowRunRequests, req)
		}
	}

	assert.True(t, len(repoGetRequests) >= 1, "Should make at least one GET repo request")
	assert.True(t, len(workflowRunRequests) >= 1, "Should make at least one workflow runs request")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	assert.Contains(t, output, "Scanning single repository", "Should log single repo scan operation")
	assert.Contains(t, output, repoFullName, "Should mention the repo being scanned")
}

// TestGitHubScan_SingleRepository_NotFound tests scanning a non-existent repository
func TestGitHubScan_SingleRepository_NotFound(t *testing.T) {
	t.Parallel()
	repoOwner := "nonexistent-org"
	repoName := "nonexistent-repo"
	repoFullName := repoOwner + "/" + repoName

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (SingleRepo 404): %s %s", r.Method, r.URL.Path)

		if r.URL.Path == "/api/v3/repos/"+repoOwner+"/"+repoName {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Not Found",
			})
		} else {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "scan",
		"--github", server.URL,
		"--token", "ghp_test_token",
		"--repo", repoFullName,
	}, nil, 10*time.Second)

	assert.NotNil(t, exitErr, "Single repo scan should fail for 404")

	requests := getRequests()
	var repoGetRequests []testutil.RecordedRequest
	for _, req := range requests {
		if req.Path == "/api/v3/repos/"+repoOwner+"/"+repoName {
			repoGetRequests = append(repoGetRequests, req)
		}
	}

	assert.True(t, len(repoGetRequests) >= 1, "Should make at least one GET repo request before failing")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	assert.Contains(t, output, "Repository not found", "Should log repository not found error")
}

// TestGitHubScan_SingleRepository_InvalidFormat tests scanning with invalid repo format
func TestGitHubScan_SingleRepository_InvalidFormat(t *testing.T) {
	t.Parallel()
	invalidRepos := []string{
		"invalid",
		"owner/repo/extra",
		"/repo",
		"owner/",
	}

	for _, invalidRepo := range invalidRepos {
		t.Run("invalid_"+invalidRepo, func(t *testing.T) {
			server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{})
			})
			defer cleanup()

			stdout, stderr, exitErr := testutil.RunCLI(t, []string{
				"gh", "scan",
				"--github", server.URL,
				"--token", "ghp_test_token",
				"--repo", invalidRepo,
			}, nil, 10*time.Second)

			assert.NotNil(t, exitErr, "Scan with invalid repo format should fail")

			output := stdout + stderr
			t.Logf("Output for '%s':\n%s", invalidRepo, output)
			assert.Contains(t, output, "Invalid repository format", "Should log invalid format error")
		})
	}
}

// TestGitHubScan_SingleRepository_WithArtifacts tests scanning a single repo with artifacts flag
func TestGitHubScan_SingleRepository_WithArtifacts(t *testing.T) {
	t.Parallel()
	repoOwner := "test-org"
	repoName := "test-repo"
	repoFullName := repoOwner + "/" + repoName

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (SingleRepo+Artifacts): %s %s", r.Method, r.URL.Path)

		switch {
		case r.URL.Path == "/api/v3/repos/"+repoOwner+"/"+repoName:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":        12345,
				"name":      repoName,
				"full_name": repoFullName,
				"html_url":  "https://github.com/" + repoFullName,
				"owner": map[string]interface{}{
					"login": repoOwner,
				},
			})

		case r.URL.Path == "/api/v3/repos/"+repoOwner+"/"+repoName+"/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{
						"id":            1001,
						"name":          "CI Build",
						"display_title": "Test workflow run",
						"html_url":      "https://github.com/" + repoFullName + "/actions/runs/1001",
						"status":        "completed",
						"repository": map[string]interface{}{
							"name":      repoName,
							"full_name": repoFullName,
							"owner": map[string]interface{}{
								"login": repoOwner,
							},
						},
					},
				},
				"total_count": 1,
			})

		case strings.Contains(r.URL.Path, "/actions/runs/1001/artifacts"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"artifacts":   []interface{}{},
				"total_count": 0,
			})

		case strings.Contains(r.URL.Path, "/actions/runs/1001/logs"):
			w.WriteHeader(http.StatusGone)

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "scan",
		"--github", server.URL,
		"--token", "ghp_test_token",
		"--repo", repoFullName,
		"--artifacts",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Single repo scan with artifacts should succeed")

	requests := getRequests()
	var artifactRequests []testutil.RecordedRequest
	for _, req := range requests {
		if strings.Contains(req.Path, "/artifacts") {
			artifactRequests = append(artifactRequests, req)
		}
	}

	assert.True(t, len(artifactRequests) >= 1, "Should make at least one artifacts request")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	assert.Contains(t, output, "Scanning single repository", "Should log single repo scan operation")
}

// TestGitHubScan_SingleRepository_MutuallyExclusive tests that --repo is mutually exclusive with other flags
func TestGitHubScan_SingleRepository_MutuallyExclusive(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{})
	})
	defer cleanup()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "repo and org",
			args: []string{"gh", "scan", "--github", server.URL, "--token", "test", "--repo", "owner/repo", "--org", "myorg"},
		},
		{
			name: "repo and user",
			args: []string{"gh", "scan", "--github", server.URL, "--token", "test", "--repo", "owner/repo", "--user", "myuser"},
		},
		{
			name: "repo and owned",
			args: []string{"gh", "scan", "--github", server.URL, "--token", "test", "--repo", "owner/repo", "--owned"},
		},
		{
			name: "repo and public",
			args: []string{"gh", "scan", "--github", server.URL, "--token", "test", "--repo", "owner/repo", "--public"},
		},
		{
			name: "repo and search",
			args: []string{"gh", "scan", "--github", server.URL, "--token", "test", "--repo", "owner/repo", "--search", "query"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, exitErr := testutil.RunCLI(t, tt.args, nil, 5*time.Second)
			assert.NotNil(t, exitErr, "Should fail when --repo is used with mutually exclusive flags")
		})
	}
}
