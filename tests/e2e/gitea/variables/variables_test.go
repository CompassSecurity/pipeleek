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

func TestGiteaVariables_Success(t *testing.T) {

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

		case "/api/v1/orgs/test-org/actions/variables":
			// Return organization variables
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"name": "ORG_VAR_1",
					"data": "org_value_1",
				},
				{
					"name": "ORG_VAR_2",
					"data": "org_value_2",
				},
			})

		case "/api/v1/repos/test-org/test-repo/actions/variables":
			// Return repository variables
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"name":  "REPO_VAR_1",
					"data":  "repo_value_1",
					"value": "repo_value_1",
				},
				{
					"name":  "REPO_VAR_2",
					"data":  "repo_value_2",
					"value": "repo_value_2",
				},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "variables",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Variables command should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify expected API calls were made
	requests := getRequests()
	assert.True(t, len(requests) >= 4, "Should make multiple API requests")

	// Verify output contains variables
	assert.Contains(t, output, "ORG_VAR_1", "Should output org variable 1")
	assert.Contains(t, output, "ORG_VAR_2", "Should output org variable 2")
	assert.Contains(t, output, "REPO_VAR_1", "Should output repo variable 1")
	assert.Contains(t, output, "REPO_VAR_2", "Should output repo variable 2")
	assert.Contains(t, output, "test-org", "Should output organization name")
	assert.Contains(t, output, "test-repo", "Should output repository name")
}

func TestGiteaVariables_Pagination(t *testing.T) {

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

		case "/api/v1/orgs/test-org/actions/variables":
			// Paginated org variables
			pageStr := r.URL.Query().Get("page")
			page, _ := strconv.Atoi(pageStr)
			if page == 0 {
				page = 1
			}

			var variables []map[string]interface{}
			// Page 1: 50 variables, Page 2: 25 variables
			switch page {
			case 1:
				for i := 1; i <= 50; i++ {
					variables = append(variables, map[string]interface{}{
						"name": "VAR_" + strconv.Itoa(i),
						"data": "value_" + strconv.Itoa(i),
					})
				}
			case 2:
				for i := 51; i <= 75; i++ {
					variables = append(variables, map[string]interface{}{
						"name": "VAR_" + strconv.Itoa(i),
						"data": "value_" + strconv.Itoa(i),
					})
				}
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(variables)

		case "/api/v1/orgs/test-org/repos":
			// No repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "variables",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Variables command should succeed with pagination")

	output := stdout + stderr
	t.Logf("Output length: %d", len(output))

	// Verify pagination worked - should have fetched 75 variables
	assert.Contains(t, output, "VAR_1", "Should have first variable")
	assert.Contains(t, output, "VAR_50", "Should have 50th variable")
	assert.Contains(t, output, "VAR_75", "Should have 75th variable")

	// Verify multiple page requests were made
	requests := getRequests()
	var orgVarRequests int
	for _, req := range requests {
		if strings.Contains(req.Path, "/orgs/test-org/actions/variables") {
			orgVarRequests++
		}
	}
	assert.GreaterOrEqual(t, orgVarRequests, 2, "Should make multiple page requests for org variables")
}

func TestGiteaVariables_EmptyResult(t *testing.T) {

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

		case "/api/v1/orgs/empty-org/actions/variables":
			// No variables
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		case "/api/v1/orgs/empty-org/repos":
			// No repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "variables",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Variables command should succeed even with no variables")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Should still show organization count
	assert.Contains(t, output, "Found organizations", "Should log organization discovery")
}

func TestGiteaVariables_MissingToken(t *testing.T) {

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "variables",
		"--gitea", "https://gitea.example.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without --token flag")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

func TestGiteaVariables_InvalidURL(t *testing.T) {

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "variables",
		"--gitea", "not-a-valid-url",
		"--token", "test-token",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail with invalid URL")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

func TestGiteaVariables_UnauthorizedAccess(t *testing.T) {

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
		"gitea", "variables",
		"--gitea", server.URL,
		"--token", "invalid-token",
	}, nil, 10*time.Second)

	assert.NotNil(t, exitErr, "Should fail with unauthorized access")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

func TestGiteaVariables_MultipleOrganizations(t *testing.T) {

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

		case "/api/v1/orgs/org-one/actions/variables":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "ORG1_VAR", "data": "org1_value"},
			})

		case "/api/v1/orgs/org-two/actions/variables":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "ORG2_VAR", "data": "org2_value"},
			})

		case "/api/v1/orgs/org-three/actions/variables":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "ORG3_VAR", "data": "org3_value"},
			})

		case "/api/v1/orgs/org-one/repos",
			"/api/v1/orgs/org-two/repos",
			"/api/v1/orgs/org-three/repos":
			// No repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "variables",
		"--gitea", server.URL,
		"--token", "test-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Variables command should succeed with multiple orgs")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify all organizations were processed (check for number, not "count=3" due to color codes)
	assert.Contains(t, output, "Found organizations", "Should find organizations")
	assert.Contains(t, output, "org-one", "Should process org-one")
	assert.Contains(t, output, "org-two", "Should process org-two")
	assert.Contains(t, output, "org-three", "Should process org-three")
	assert.Contains(t, output, "ORG1_VAR", "Should output org1 variable")
	assert.Contains(t, output, "ORG2_VAR", "Should output org2 variable")
	assert.Contains(t, output, "ORG3_VAR", "Should output org3 variable")
}
