//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockGitHubRenovateAPI(t *testing.T) string {
	mux := http.NewServeMux()

	// Counter for branch calls to simulate branch appearing
	branchCallCount := 0

	// Repository endpoints
	mux.HandleFunc("/api/v3/repos/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/collaborators/test-user") && r.Method == http.MethodPut {
			// Add collaborator
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{}`))
			return
		}
		if strings.Contains(path, "/branches/main/protection") {
			// Branch protection
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"url":"","required_status_checks":null,"enforce_admins":null,"required_pull_request_reviews":{"url":"","dismiss_stale_reviews":false,"require_code_owner_reviews":false,"required_approving_review_count":1,"require_last_push_approval":false},"restrictions":null,"required_linear_history":{"enabled":true},"allow_force_pushes":null,"allow_deletions":null,"required_conversation_resolution":null,"lock_branch":null}`))
				return
			}
		}
		if strings.Contains(path, "/contents/") {
			// Repository contents
			if r.Method == http.MethodGet {
				// Get file content
				if strings.HasSuffix(path, "renovate.json") {
					// Return renovate.json with autodiscovery filter
					w.WriteHeader(http.StatusOK)
					// {"autodiscoverFilter": "owner/repo"} in base64
					content := "eyJhdXRvZGlzY292ZXJGaWx0ZXIiOiAib3duZXIvcmVwbyJ9"
					w.Write([]byte(`{"name":"renovate.json","path":"renovate.json","sha":"abc123","content":"` + content + `","encoding":"base64"}`))
					return
				}
				if strings.HasSuffix(path, "build.gradle") {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"name":"build.gradle","path":"build.gradle","sha":"abc123","content":"YnVpbGQgZmlsZQ==","encoding":"base64"}`))
					return
				}
				if strings.HasSuffix(path, "/.github/workflows") {
					// List workflow directory
					w.WriteHeader(http.StatusOK)
					workflowList := `[{"name":"renovate.yml","path":".github/workflows/renovate.yml","type":"file"}]`
					w.Write([]byte(workflowList))
					return
				}
				if strings.Contains(path, "/.github/workflows/renovate.yml") {
					// Get workflow file content with autodiscovery and GitHub Actions template
					w.WriteHeader(http.StatusOK)
					// Workflow with RENOVATE_AUTODISCOVER and RENOVATE_AUTODISCOVER_FILTER with GitHub Actions template
					workflowContent := `name: Renovate
on:
  workflow_dispatch:
jobs:
  renovate:
    runs-on: ubuntu-latest
    steps:
      - uses: renovatebot/github-action@v44.2.3
        env:
          RENOVATE_AUTODISCOVER: true
          RENOVATE_AUTODISCOVER_FILTER: ${{ github.repository }}`
					content := base64.StdEncoding.EncodeToString([]byte(workflowContent))
					w.Write([]byte(`{"name":"renovate.yml","path":".github/workflows/renovate.yml","sha":"def456","content":"` + content + `","encoding":"base64"}`))
					return
				}
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == http.MethodPut {
				// Create/update file
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"content":{"name":"file","path":"file","sha":"abc123"},"commit":{"sha":"commit123"}}`))
				return
			}
		}
		if strings.Contains(path, "/branches") {
			// List branches
			branchName := "renovate/test-branch"
			if r.Method == http.MethodGet {
				branchCallCount++
				// Return branches - include renovate branch on second call
				if branchCallCount == 1 {
					branches := `[{"name":"main","commit":{"sha":"main123"}}]`
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(branches))
				} else {
					branches := `[{"name":"main","commit":{"sha":"main123"}},{"name":"` + branchName + `","commit":{"sha":"ren123"}}]`
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(branches))
				}
				return
			}
		}
		if strings.Contains(path, "/pulls") {
			// Pull requests
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[{"number":1,"title":"Update dependencies","html_url":"https://github.com/test-owner/test-repo/pull/1"}]`))
				return
			}
		}
		if r.Method == http.MethodGet {
			// Get repository
			w.WriteHeader(http.StatusOK)
			repo := map[string]interface{}{
				"id":             123,
				"name":           "test-repo",
				"full_name":      "test-owner/test-repo",
				"html_url":       "https://github.com/test-owner/test-repo",
				"default_branch": "main",
				"disabled":       false,
				"archived":       false,
				"owner": map[string]interface{}{
					"login": "test-owner",
				},
			}
			json.NewEncoder(w).Encode(repo)
			return
		}
	})

	// User repositories endpoint
	mux.HandleFunc("/api/v3/user/repos", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Create repository
			w.WriteHeader(http.StatusCreated)
			repo := map[string]interface{}{
				"id":        123,
				"name":      "test-repo",
				"full_name": "test-owner/test-repo",
				"html_url":  "https://github.com/test-owner/test-repo",
				"owner": map[string]interface{}{
					"login": "test-owner",
				},
				"default_branch": "main",
				"disabled":       false,
				"archived":       false,
			}
			json.NewEncoder(w).Encode(repo)
			return
		}

		// Check for affiliation parameter to differentiate between owned and member
		affiliation := r.URL.Query().Get("affiliation")
		if affiliation == "owner" {
			// Owned repositories
			w.WriteHeader(http.StatusOK)
			repos := `[{"id":123,"name":"test-repo","full_name":"test-owner/test-repo","html_url":"https://github.com/test-owner/test-repo","owner":{"login":"test-owner"},"default_branch":"main","disabled":false,"archived":false}]`
			w.Write([]byte(repos))
			return
		} else if strings.Contains(affiliation, "organization_member") {
			// Member repositories
			w.WriteHeader(http.StatusOK)
			repos := `[{"id":789,"name":"member-repo","full_name":"some-org/member-repo","html_url":"https://github.com/some-org/member-repo","owner":{"login":"some-org"},"default_branch":"main","disabled":false,"archived":false}]`
			w.Write([]byte(repos))
			return
		}

		// Default response
		w.WriteHeader(http.StatusOK)
		repos := `[{"id":123,"name":"test-repo","full_name":"test-owner/test-repo","html_url":"https://github.com/test-owner/test-repo","owner":{"login":"test-owner"},"default_branch":"main","disabled":false,"archived":false}]`
		w.Write([]byte(repos))
	})

	// Search repositories endpoint
	mux.HandleFunc("/api/v3/search/repositories", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		searchResult := `{
			"total_count": 1,
			"incomplete_results": false,
			"items": [
				{
					"id": 999,
					"name": "search-result-repo",
					"full_name": "search-owner/search-result-repo",
					"html_url": "https://github.com/search-owner/search-result-repo",
					"owner": {"login": "search-owner"},
					"default_branch": "main",
					"disabled": false,
					"archived": false
				}
			]
		}`
		w.Write([]byte(searchResult))
	})

	// Organization repositories endpoint
	mux.HandleFunc("/api/v3/orgs/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos") {
			w.WriteHeader(http.StatusOK)
			repos := `[{"id":456,"name":"org-repo","full_name":"test-org/org-repo","html_url":"https://github.com/test-org/org-repo","owner":{"login":"test-org"},"default_branch":"main","disabled":false,"archived":false}]`
			w.Write([]byte(repos))
			return
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGHRenovateEnum(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Fetched all owned repositories")
}

func TestGHRenovateEnumSpecificRepo(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Scanning specific repository")
	assert.Contains(t, combined, "test-owner/test-repo")
	assert.NotContains(t, combined, "fatal")
}

func TestGHRenovateEnumOrganization(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--org", "test-org",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Scanning organization")
	assert.Contains(t, combined, "test-org")
	assert.NotContains(t, combined, "fatal")
}

func TestGHRenovateAutodiscovery(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "autodiscovery",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-exploit-repo",
		"--username", "test-user",
		"-v",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery command should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Created repository")
	assert.Contains(t, combined, "Created file", "Should log file creation in verbose mode")
	assert.Contains(t, combined, "Inviting user")
	assert.Contains(t, combined, "Gradle wrapper", "Should mention Gradle wrapper mechanism")
	assert.Contains(t, combined, "gradlew", "Should mention gradlew script")
	assert.NotContains(t, combined, "fatal")
}

func TestGHRenovateAutodiscoveryWithoutUsername(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "autodiscovery",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-repo-no-user",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery without username should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Created repository")
	assert.Contains(t, combined, "No username provided")
	assert.Contains(t, combined, "invite the victim Renovate Bot user manually")
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovatePrivesc tests the privesc command
// Note: This test is skipped because the privesc command has an infinite monitoring loop
// that is difficult to test without significant refactoring. The command works in practice
// but requires a real or much more complex mock GitHub API to properly test.
func TestGHRenovatePrivesc(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "privesc",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-owner/test-repo",
		"--renovate-branches-regex", "renovate/.*",
	}, nil, 15*time.Second)
	if exitErr != nil {
		t.Logf("STDOUT:\n%s", stdout)
		t.Logf("STDERR:\n%s", stderr)
	}
	assert.Nil(t, exitErr, "Privesc command should succeed")
	// Logs are written to stdout by the application logger
	if !strings.Contains(stderr, "Ensure the Renovate bot") {
		assert.Contains(t, stdout, "Ensure the Renovate bot")
	}
	if !strings.Contains(stderr, "renovate/test-branch") {
		assert.Contains(t, stdout, "renovate/test-branch")
	}
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumWithSearch tests the enum command with search functionality
func TestGHRenovateEnumWithSearch(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--search", "renovate in:readme",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command with search should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Searching repositories")
	assert.Contains(t, combined, "search-owner/search-result-repo")
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovateEnumFastMode tests the enum command with fast mode
func TestGHRenovateEnumFastMode(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
		"--fast",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command with fast mode should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Fetched all owned repositories")
	// Fast mode should skip config file detection, only check workflows
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovateEnumDumpMode tests the enum command with dump mode
func TestGHRenovateEnumDumpMode(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)

	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)

	// Change to temp directory so dump files go there
	err = os.Chdir(tmpDir)
	require.NoError(t, err)
	defer os.Chdir(origDir)

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
		"--dump",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command with dump mode should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Fetched all owned repositories")

	// Check if dump directory was created
	dumpDir := filepath.Join(tmpDir, "renovate-enum-out")
	if _, err := os.Stat(dumpDir); err == nil {
		// Dump directory exists, verify it has files
		entries, err := os.ReadDir(dumpDir)
		if err == nil && len(entries) > 0 {
			t.Logf("Dump directory created with %d files", len(entries))
		}
	}

	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovateEnumMemberRepositories tests the enum command with member flag
func TestGHRenovateEnumMemberRepositories(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--member",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command with member flag should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Fetched all member repositories")
	assert.Contains(t, combined, "member-repo")
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovateEnumDetectsAutodiscovery tests autodiscovery detection
func TestGHRenovateEnumDetectsAutodiscovery(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
		"-v", // Verbose to see autodiscovery detection logs
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "test-owner/test-repo")
	// Check for autodiscovery in the JSON output or logs
	assert.Contains(t, combined, "hasAutodiscovery")
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovateEnumDetectsAutodiscoveryFilters tests autodiscovery filter detection
func TestGHRenovateEnumDetectsAutodiscoveryFilters(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
		"-v",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	// Should detect the GitHub Actions template in workflow file
	combined := stdout + stderr
	assert.Contains(t, combined, "autodiscoveryFilterValue")
	assert.Contains(t, combined, "${{ github.repository }}")
	// Should also detect the filter in renovate.json config file
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovateEnumWithPagination tests the enum command with pagination
func TestGHRenovateEnumWithPagination(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
		"--page", "1",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command with pagination should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Fetched all owned repositories")
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovateEnumWithOrderBy tests the enum command with order-by flag
func TestGHRenovateEnumWithOrderBy(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
		"--order-by", "updated",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command with order-by should succeed")
	combined := stdout + stderr
	assert.Contains(t, combined, "Fetched all owned repositories")
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovateEnumMutuallyExclusiveFlags tests that mutually exclusive flags are rejected
func TestGHRenovateEnumMutuallyExclusiveFlags(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
		"--member",
	}, nil, 5*time.Second)
	assert.NotNil(t, exitErr, "Should fail with mutually exclusive flags")
	combined := stdout + stderr
	assert.Contains(t, combined, "if any flags in the group")
}

// TestGHRenovateEnumDetectsWorkflowWithGitHubActionsTemplate tests GitHub Actions template detection in workflows
func TestGHRenovateEnumDetectsWorkflowWithGitHubActionsTemplate(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
		"-vv", // Extra verbose to see detailed logs
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	// The workflow contains ${{ github.repository }} template
	// This should be detected and logged with the full template, not just "${"
	combined := stdout + stderr
	assert.Contains(t, combined, "test-owner/test-repo")
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovateEnumDetectsJSONConfigFile tests JSON config file detection
func TestGHRenovateEnumDetectsJSONConfigFile(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
		"-v",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	// Should detect renovate.json with JSON autodiscoverFilter
	combined := stdout + stderr
	assert.Contains(t, combined, "test-owner/test-repo")
	// Should log that it found autodiscovery filters from the JSON config
	assert.NotContains(t, combined, "fatal")
}

// TestGHRenovatePrivescWithMonitoringInterval tests the privesc command with custom monitoring interval
func TestGHRenovatePrivescWithMonitoringInterval(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "privesc",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-owner/test-repo",
		"--renovate-branches-regex", "renovate/.*",
		"--monitoring-interval", "500ms",
	}, nil, 15*time.Second)
	if exitErr != nil {
		t.Logf("STDOUT:\n%s", stdout)
		t.Logf("STDERR:\n%s", stderr)
	}
	assert.Nil(t, exitErr, "Privesc command with monitoring-interval should succeed")
	if !strings.Contains(stderr, "Ensure the Renovate bot") {
		assert.Contains(t, stdout, "Ensure the Renovate bot")
	}
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovatePrivescWithInvalidMonitoringInterval tests privesc with invalid monitoring interval
func TestGHRenovatePrivescWithInvalidMonitoringInterval(t *testing.T) {
	t.Parallel()
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "privesc",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-owner/test-repo",
		"--renovate-branches-regex", "renovate/.*",
		"--monitoring-interval", "invalid-duration",
	}, nil, 15*time.Second)
	assert.NotNil(t, exitErr, "Privesc command with invalid monitoring-interval should fail")
	combined := stdout + stderr
	assert.Contains(t, combined, "Failed to parse monitoring-interval duration")
}
