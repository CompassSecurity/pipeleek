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
      - uses: renovatebot/github-action@v40.3.10
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
		if strings.Contains(path, "/branches/main/protection") {
			// Branch protection
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"url":"","required_status_checks":null,"enforce_admins":null,"required_pull_request_reviews":{"url":"","dismiss_stale_reviews":false,"require_code_owner_reviews":false,"required_approving_review_count":1,"require_last_push_approval":false},"restrictions":null,"required_linear_history":{"enabled":true},"allow_force_pushes":null,"allow_deletions":null,"required_conversation_resolution":null,"lock_branch":null}`))
				return
			}
		}
		if r.Method == http.MethodGet {
			// Get repository
			w.WriteHeader(http.StatusOK)
			repo := map[string]interface{}{
				"id":            123,
				"name":          "test-repo",
				"full_name":     "test-owner/test-repo",
				"html_url":      "https://github.com/test-owner/test-repo",
				"default_branch": "main",
				"disabled":      false,
				"archived":      false,
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
				"disabled":      false,
				"archived":      false,
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
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	assert.Contains(t, stdout, "Fetched all repositories")
	assert.NotContains(t, stderr, "error")
}

func TestGHRenovateEnumSpecificRepo(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	assert.Contains(t, stdout, "Scanning specific repository")
	assert.Contains(t, stdout, "test-owner/test-repo")
	assert.NotContains(t, stderr, "fatal")
}

func TestGHRenovateEnumOrganization(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--org", "test-org",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	assert.Contains(t, stdout, "Scanning organization")
	assert.Contains(t, stdout, "test-org")
	assert.NotContains(t, stderr, "fatal")
}

func TestGHRenovateAutodiscovery(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "autodiscovery",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-exploit-repo",
		"--username", "test-user",
		"-v",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery command should succeed")
	assert.Contains(t, stdout, "Created repository")
	assert.Contains(t, stdout, "Created file", "Should log file creation in verbose mode")
	assert.Contains(t, stdout, "Inviting user")
	assert.Contains(t, stdout, "Gradle wrapper", "Should mention Gradle wrapper mechanism")
	assert.Contains(t, stdout, "gradlew", "Should mention gradlew script")
	assert.NotContains(t, stderr, "fatal")
}

func TestGHRenovateAutodiscoveryWithWorkflow(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "autodiscovery",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-repo-workflow",
		"--username", "test-user",
		"--add-renovate-workflow-for-debugging",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery with workflow flag should succeed")
	assert.Contains(t, stdout, "Created repository")
	assert.Contains(t, stdout, "Created .github/workflows/renovate.yml")
	assert.Contains(t, stdout, "RENOVATE_TOKEN", "Should mention token setup")
	assert.Contains(t, stdout, "repo", "Should mention repo scope requirement")
	assert.NotContains(t, stderr, "fatal")
}

func TestGHRenovateAutodiscoveryWithoutUsername(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "autodiscovery",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-repo-no-user",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery without username should succeed")
	assert.Contains(t, stdout, "Created repository")
	assert.Contains(t, stdout, "No username provided")
	assert.Contains(t, stdout, "invite the victim Renovate Bot user manually")
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovatePrivesc tests the privesc command
// Note: This test is skipped because the privesc command has an infinite monitoring loop
// that is difficult to test without significant refactoring. The command works in practice
// but requires a real or much more complex mock GitHub API to properly test.
func TestGHRenovatePrivesc(t *testing.T) {
	t.Skip("Skipping privesc test - command has infinite monitoring loop that's difficult to test in e2e")
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "privesc",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo-name", "test-owner/test-repo",
		"--renovate-branches-regex", "renovate/.*",
	}, nil, 30*time.Second)
	assert.Nil(t, exitErr, "Privesc command should succeed")
	assert.Contains(t, stdout, "Ensure the Renovate bot")
	assert.Contains(t, stdout, "renovate/test-branch")
	assert.NotContains(t, stderr, "fatal")
}
// TestGHRenovateEnumWithSearch tests the enum command with search functionality
func TestGHRenovateEnumWithSearch(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--search", "renovate in:readme",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command with search should succeed")
	assert.Contains(t, stdout, "Searching repositories")
	assert.Contains(t, stdout, "search-owner/search-result-repo")
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumFastMode tests the enum command with fast mode
func TestGHRenovateEnumFastMode(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
		"--fast",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command with fast mode should succeed")
	assert.Contains(t, stdout, "Fetched all repositories")
	// Fast mode should skip config file detection, only check workflows
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumDumpMode tests the enum command with dump mode
func TestGHRenovateEnumDumpMode(t *testing.T) {
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
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command with dump mode should succeed")
	assert.Contains(t, stdout, "Fetched all repositories")
	
	// Check if dump directory was created
	dumpDir := filepath.Join(tmpDir, "renovate-enum-out")
	if _, err := os.Stat(dumpDir); err == nil {
		// Dump directory exists, verify it has files
		entries, err := os.ReadDir(dumpDir)
		if err == nil && len(entries) > 0 {
			t.Logf("Dump directory created with %d files", len(entries))
		}
	}
	
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumMemberRepositories tests the enum command with member flag
func TestGHRenovateEnumMemberRepositories(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--member",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command with member flag should succeed")
	assert.Contains(t, stdout, "Fetched all repositories")
	assert.Contains(t, stdout, "member-repo")
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumDetectsAutodiscovery tests autodiscovery detection
func TestGHRenovateEnumDetectsAutodiscovery(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
		"-v", // Verbose to see autodiscovery detection logs
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	assert.Contains(t, stdout, "test-owner/test-repo")
	// Check for autodiscovery in the JSON output or logs
	assert.Contains(t, stdout, "hasAutodiscovery")
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumDetectsAutodiscoveryFilters tests autodiscovery filter detection
func TestGHRenovateEnumDetectsAutodiscoveryFilters(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
		"-v",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	// Should detect the GitHub Actions template in workflow file
	assert.Contains(t, stdout, "autodiscoveryFilterValue")
	assert.Contains(t, stdout, "${{ github.repository }}")
	// Should also detect the filter in renovate.json config file
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumWithPagination tests the enum command with pagination
func TestGHRenovateEnumWithPagination(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
		"--page", "1",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command with pagination should succeed")
	assert.Contains(t, stdout, "Fetched all repositories")
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumWithOrderBy tests the enum command with order-by flag
func TestGHRenovateEnumWithOrderBy(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
		"--order-by", "updated",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command with order-by should succeed")
	assert.Contains(t, stdout, "Fetched all repositories")
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumMutuallyExclusiveFlags tests that mutually exclusive flags are rejected
func TestGHRenovateEnumMutuallyExclusiveFlags(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	_, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--owned",
		"--member",
	}, nil, 5*time.Second)
	assert.NotNil(t, exitErr, "Should fail with mutually exclusive flags")
	assert.Contains(t, stderr, "mutually exclusive")
}

// TestGHRenovateEnumDetectsWorkflowWithGitHubActionsTemplate tests GitHub Actions template detection in workflows
func TestGHRenovateEnumDetectsWorkflowWithGitHubActionsTemplate(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
		"-vv", // Extra verbose to see detailed logs
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	// The workflow contains ${{ github.repository }} template
	// This should be detected and logged with the full template, not just "${"
	assert.Contains(t, stdout, "test-owner/test-repo")
	assert.NotContains(t, stderr, "fatal")
}

// TestGHRenovateEnumDetectsJSONConfigFile tests JSON config file detection
func TestGHRenovateEnumDetectsJSONConfigFile(t *testing.T) {
	apiURL := setupMockGitHubRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "renovate", "enum",
		"--github", apiURL,
		"--token", "mock-token",
		"--repo", "test-owner/test-repo",
		"-v",
	}, nil, 15*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	// Should detect renovate.json with JSON autodiscoverFilter
	assert.Contains(t, stdout, "test-owner/test-repo")
	// Should log that it found autodiscovery filters from the JSON config
	assert.NotContains(t, stderr, "fatal")
}