package e2e

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGiteaSecrets_Success(t *testing.T) {

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// Return list of all user repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        100,
					"name":      "test-repo",
					"full_name": "test-org/test-repo",
					"owner":     map[string]interface{}{"username": "test-org", "login": "test-org"},
				},
			})

		case "/api/v1/user/orgs":
			// Return list of organizations
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-org", "username": "test-org"},
			})

		case "/api/v1/orgs/test-org/actions/secrets":
			// Return organization secrets
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"name": "ORG_SECRET_1",
				},
				{
					"name": "ORG_SECRET_2",
				},
			})

		case "/api/v1/repos/test-org/test-repo/actions/secrets":
			// Return repository secrets
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"name": "REPO_SECRET_1",
				},
				{
					"name": "REPO_SECRET_2",
				},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Secrets command should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify expected API calls were made
	requests := getRequests()
	assert.True(t, len(requests) >= 4, "Should make multiple API requests")

	// Verify output contains secrets
	assert.Contains(t, output, "ORG_SECRET_1", "Should output org secret 1")
	assert.Contains(t, output, "ORG_SECRET_2", "Should output org secret 2")
	assert.Contains(t, output, "REPO_SECRET_1", "Should output repo secret 1")
	assert.Contains(t, output, "REPO_SECRET_2", "Should output repo secret 2")
	assert.Contains(t, output, "test-org", "Should output organization name")
	assert.Contains(t, output, "test-repo", "Should output repository name")
}

func TestGiteaSecrets_OrgPagination(t *testing.T) {

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// No user repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		case "/api/v1/user/orgs":
			// Return list of organizations
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-org", "username": "test-org"},
			})

		case "/api/v1/orgs/test-org/actions/secrets":
			// Paginated org secrets
			pageStr := r.URL.Query().Get("page")
			page, _ := strconv.Atoi(pageStr)
			if page == 0 {
				page = 1
			}

			var secrets []map[string]interface{}
			// Page 1: 50 secrets, Page 2: 25 secrets
			switch page {
			case 1:
				for i := 1; i <= 50; i++ {
					secrets = append(secrets, map[string]interface{}{
						"name": "SECRET_" + strconv.Itoa(i),
					})
				}
			case 2:
				for i := 51; i <= 75; i++ {
					secrets = append(secrets, map[string]interface{}{
						"name": "SECRET_" + strconv.Itoa(i),
					})
				}
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(secrets)

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Secrets command should succeed with pagination")

	output := stdout + stderr
	t.Logf("Output length: %d", len(output))

	// Verify pagination worked - should have fetched 75 secrets
	assert.Contains(t, output, "SECRET_1", "Should have first secret")
	assert.Contains(t, output, "SECRET_50", "Should have 50th secret")
	assert.Contains(t, output, "SECRET_75", "Should have 75th secret")

	// Verify multiple page requests were made
	requests := getRequests()
	var orgSecretRequests int
	for _, req := range requests {
		if strings.Contains(req.Path, "/orgs/test-org/actions/secrets") {
			orgSecretRequests++
		}
	}
	assert.GreaterOrEqual(t, orgSecretRequests, 2, "Should make multiple page requests for org secrets")
}

func TestGiteaSecrets_RepoPagination(t *testing.T) {

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// Return one repository
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        100,
					"name":      "test-repo",
					"full_name": "test-user/test-repo",
					"owner":     map[string]interface{}{"username": "test-user", "login": "test-user"},
				},
			})

		case "/api/v1/user/orgs":
			// No organizations
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		case "/api/v1/repos/test-user/test-repo/actions/secrets":
			// Paginated repo secrets
			pageStr := r.URL.Query().Get("page")
			page, _ := strconv.Atoi(pageStr)
			if page == 0 {
				page = 1
			}

			var secrets []map[string]interface{}
			// Page 1: 50 secrets, Page 2: 30 secrets
			switch page {
			case 1:
				for i := 1; i <= 50; i++ {
					secrets = append(secrets, map[string]interface{}{
						"name": "REPO_SECRET_" + strconv.Itoa(i),
					})
				}
			case 2:
				for i := 51; i <= 80; i++ {
					secrets = append(secrets, map[string]interface{}{
						"name": "REPO_SECRET_" + strconv.Itoa(i),
					})
				}
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(secrets)

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Secrets command should succeed with repo pagination")

	output := stdout + stderr
	t.Logf("Output length: %d", len(output))

	// Verify pagination worked - should have fetched 80 repo secrets
	assert.Contains(t, output, "REPO_SECRET_1", "Should have first repo secret")
	assert.Contains(t, output, "REPO_SECRET_50", "Should have 50th repo secret")
	assert.Contains(t, output, "REPO_SECRET_80", "Should have 80th repo secret")

	// Verify multiple page requests were made
	requests := getRequests()
	var repoSecretRequests int
	for _, req := range requests {
		if strings.Contains(req.Path, "/repos/test-user/test-repo/actions/secrets") {
			repoSecretRequests++
		}
	}
	assert.GreaterOrEqual(t, repoSecretRequests, 2, "Should make multiple page requests for repo secrets")
}

func TestGiteaSecrets_MultipleReposPagination(t *testing.T) {

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// Return paginated list of repositories
			pageStr := r.URL.Query().Get("page")
			page, _ := strconv.Atoi(pageStr)
			if page == 0 {
				page = 1
			}

			var repos []map[string]interface{}
			// Page 1: 50 repos, Page 2: 25 repos
			switch page {
			case 1:
				for i := 1; i <= 50; i++ {
					repos = append(repos, map[string]interface{}{
						"id":        100 + i,
						"name":      "repo-" + strconv.Itoa(i),
						"full_name": "test-user/repo-" + strconv.Itoa(i),
						"owner":     map[string]interface{}{"username": "test-user", "login": "test-user"},
					})
				}
			case 2:
				for i := 51; i <= 75; i++ {
					repos = append(repos, map[string]interface{}{
						"id":        100 + i,
						"name":      "repo-" + strconv.Itoa(i),
						"full_name": "test-user/repo-" + strconv.Itoa(i),
						"owner":     map[string]interface{}{"username": "test-user", "login": "test-user"},
					})
				}
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(repos)

		case "/api/v1/user/orgs":
			// No organizations
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		default:
			// Handle repo secrets - return 1 secret per repo for simplicity
			if strings.Contains(r.URL.Path, "/actions/secrets") {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{"name": "SECRET_1"},
				})
			} else {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
			}
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 30*time.Second)

	assert.Nil(t, exitErr, "Secrets command should succeed with multiple repos pagination")

	output := stdout + stderr
	t.Logf("Output length: %d", len(output))

	// Verify that repositories were paginated
	assert.Contains(t, output, "repo-1", "Should process first repo")
	assert.Contains(t, output, "repo-50", "Should process 50th repo")
	assert.Contains(t, output, "repo-75", "Should process 75th repo")

	// Verify multiple page requests were made for repos
	requests := getRequests()
	var repoListRequests int
	for _, req := range requests {
		if req.Path == "/api/v1/user/repos" {
			repoListRequests++
		}
	}
	assert.GreaterOrEqual(t, repoListRequests, 2, "Should make multiple page requests for listing repos")
}

func TestGiteaSecrets_MultipleOrgsPagination(t *testing.T) {

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// No repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		case "/api/v1/user/orgs":
			// Return paginated list of organizations
			pageStr := r.URL.Query().Get("page")
			page, _ := strconv.Atoi(pageStr)
			if page == 0 {
				page = 1
			}

			var orgs []map[string]interface{}
			// Page 1: 50 orgs, Page 2: 30 orgs
			switch page {
			case 1:
				for i := 1; i <= 50; i++ {
					orgs = append(orgs, map[string]interface{}{
						"id":       i,
						"name":     "org-" + strconv.Itoa(i),
						"username": "org-" + strconv.Itoa(i),
					})
				}
			case 2:
				for i := 51; i <= 80; i++ {
					orgs = append(orgs, map[string]interface{}{
						"id":       i,
						"name":     "org-" + strconv.Itoa(i),
						"username": "org-" + strconv.Itoa(i),
					})
				}
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(orgs)

		default:
			// Handle org secrets - return 1 secret per org for simplicity
			if strings.Contains(r.URL.Path, "/actions/secrets") {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{"name": "ORG_SECRET"},
				})
			} else {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
			}
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 30*time.Second)

	assert.Nil(t, exitErr, "Secrets command should succeed with multiple orgs pagination")

	output := stdout + stderr
	t.Logf("Output length: %d", len(output))

	// Verify that organizations were paginated
	assert.Contains(t, output, "org-1", "Should process first org")
	assert.Contains(t, output, "org-50", "Should process 50th org")
	assert.Contains(t, output, "org-80", "Should process 80th org")

	// Verify multiple page requests were made for orgs
	requests := getRequests()
	var orgListRequests int
	for _, req := range requests {
		if req.Path == "/api/v1/user/orgs" {
			orgListRequests++
		}
	}
	assert.GreaterOrEqual(t, orgListRequests, 2, "Should make multiple page requests for listing orgs")
}

func TestGiteaSecrets_EmptyResult(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// No user repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		case "/api/v1/user/orgs":
			// Return one organization
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "empty-org", "username": "empty-org"},
			})

		case "/api/v1/orgs/empty-org/actions/secrets":
			// No secrets
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Secrets command should succeed even with no secrets")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Should still show organization count
	assert.Contains(t, output, "Found organizations", "Should log organization discovery")
}

func TestGiteaSecrets_MissingToken(t *testing.T) {

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", "https://gitea.example.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without --token flag")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	assert.Contains(t, output, "required configuration missing", "Should indicate missing required configuration")
}

func TestGiteaSecrets_InvalidURL(t *testing.T) {

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", "not-a-valid-url",
		"--token", "test-token",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail with invalid URL")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

func TestGiteaSecrets_UnauthorizedAccess(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// Return unauthorized
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Unauthorized",
			})

		case "/api/v1/user/orgs":
			// Return unauthorized
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Unauthorized",
			})

		default:
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Unauthorized",
			})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "invalid-token",
	}, nil, 10*time.Second)

	assert.NotNil(t, exitErr, "Should fail with unauthorized access")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

func TestGiteaSecrets_MultipleOrganizations(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// No user repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		case "/api/v1/user/orgs":
			// Return multiple organizations
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "org-one", "username": "org-one"},
				{"id": 2, "name": "org-two", "username": "org-two"},
				{"id": 3, "name": "org-three", "username": "org-three"},
			})

		case "/api/v1/orgs/org-one/actions/secrets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "ORG1_SECRET"},
			})

		case "/api/v1/orgs/org-two/actions/secrets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "ORG2_SECRET"},
			})

		case "/api/v1/orgs/org-three/actions/secrets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "ORG3_SECRET"},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Secrets command should succeed with multiple orgs")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify all organizations were processed
	assert.Contains(t, output, "Found organizations", "Should find organizations")
	assert.Contains(t, output, "org-one", "Should process org-one")
	assert.Contains(t, output, "org-two", "Should process org-two")
	assert.Contains(t, output, "org-three", "Should process org-three")
	assert.Contains(t, output, "ORG1_SECRET", "Should output org1 secret")
	assert.Contains(t, output, "ORG2_SECRET", "Should output org2 secret")
	assert.Contains(t, output, "ORG3_SECRET", "Should output org3 secret")
}

func TestGiteaSecrets_MultipleRepositories(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// Return multiple repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        1,
					"name":      "repo-one",
					"full_name": "user/repo-one",
					"owner":     map[string]interface{}{"username": "user", "login": "user"},
				},
				{
					"id":        2,
					"name":      "repo-two",
					"full_name": "user/repo-two",
					"owner":     map[string]interface{}{"username": "user", "login": "user"},
				},
				{
					"id":        3,
					"name":      "repo-three",
					"full_name": "user/repo-three",
					"owner":     map[string]interface{}{"username": "user", "login": "user"},
				},
			})

		case "/api/v1/user/orgs":
			// No organizations
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		case "/api/v1/repos/user/repo-one/actions/secrets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "REPO1_SECRET"},
			})

		case "/api/v1/repos/user/repo-two/actions/secrets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "REPO2_SECRET"},
			})

		case "/api/v1/repos/user/repo-three/actions/secrets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "REPO3_SECRET"},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Secrets command should succeed with multiple repos")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify all repositories were processed
	assert.Contains(t, output, "Found repositories", "Should find repositories")
	assert.Contains(t, output, "repo-one", "Should process repo-one")
	assert.Contains(t, output, "repo-two", "Should process repo-two")
	assert.Contains(t, output, "repo-three", "Should process repo-three")
	assert.Contains(t, output, "REPO1_SECRET", "Should output repo1 secret")
	assert.Contains(t, output, "REPO2_SECRET", "Should output repo2 secret")
	assert.Contains(t, output, "REPO3_SECRET", "Should output repo3 secret")
}

func TestGiteaSecrets_PartialFailure(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})

		case "/api/v1/user/repos":
			// Return two repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        1,
					"name":      "good-repo",
					"full_name": "user/good-repo",
					"owner":     map[string]interface{}{"username": "user", "login": "user"},
				},
				{
					"id":        2,
					"name":      "bad-repo",
					"full_name": "user/bad-repo",
					"owner":     map[string]interface{}{"username": "user", "login": "user"},
				},
			})

		case "/api/v1/user/orgs":
			// Return two organizations
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "good-org", "username": "good-org"},
				{"id": 2, "name": "bad-org", "username": "bad-org"},
			})

		case "/api/v1/orgs/good-org/actions/secrets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "GOOD_ORG_SECRET"},
			})

		case "/api/v1/orgs/bad-org/actions/secrets":
			// Simulate error for bad-org
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Forbidden",
			})

		case "/api/v1/repos/user/good-repo/actions/secrets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "GOOD_REPO_SECRET"},
			})

		case "/api/v1/repos/user/bad-repo/actions/secrets":
			// Simulate error for bad-repo
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Forbidden",
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "secrets",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 10*time.Second)

	// Should succeed overall even with partial failures
	assert.Nil(t, exitErr, "Secrets command should succeed even with partial failures")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify successful fetches are in output
	assert.Contains(t, output, "GOOD_ORG_SECRET", "Should output successful org secret")
	assert.Contains(t, output, "GOOD_REPO_SECRET", "Should output successful repo secret")

	// Verify warnings for failed fetches
	assert.Contains(t, output, "warn", "Should log warnings for failures")
}
