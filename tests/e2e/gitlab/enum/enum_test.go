package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabEnum(t *testing.T) {

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       1,
				"username": "testuser",
				"email":    "test@example.com",
			})

		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-group"},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "enum",
		"--url", server.URL,
		"--token", "glpat-test",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Enum command should succeed")

	// Verify API calls
	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

func TestGitLabEnum_WithHTMLExport(t *testing.T) {
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       1,
				"username": "testuser",
				"name":     "Test User",
				"email":    "test@example.com",
			})
		case "/api/v4/personal_access_tokens/self":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":            99,
				"name":          "test-token",
				"revoked":       false,
				"created_at":    "2026-07-06T08:00:00Z",
				"description":   "e2e token",
				"scopes":        []string{"api", "read_api"},
				"user_id":       1,
				"last_used_at":  "2026-07-06T08:00:00Z",
				"active":        true,
				"expires_at":    "",
				"last_used_ips": []string{"127.0.0.1"},
			})
		case "/api/v4/personal_access_tokens/self/associations":
			w.Header().Set("x-next-page", "")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"groups": []map[string]interface{}{
					{
						"id":              7,
						"web_url":         serverURL(serverURLFromRequest(r), "/groups/security-team"),
						"name":            "security-team",
						"parent_id":       nil,
						"organization_id": 1,
						"access_levels":   50,
						"visibility":      "private",
					},
				},
				"projects": []map[string]interface{}{
					{
						"id":                  13,
						"description":         "",
						"name":                "security-tools",
						"name_with_namespace": "security-team / security-tools",
						"path":                "security-tools",
						"path_with_namespace": "security-team/security-tools",
						"created_at":          "2026-07-06T08:00:00Z",
						"access_levels": map[string]interface{}{
							"project_access_level": 0,
							"group_access_level":   50,
						},
						"visibility": "private",
						"web_url":    serverURL(serverURLFromRequest(r), "/security-team/security-tools"),
						"namespace": map[string]interface{}{
							"id":         7,
							"name":       "security-team",
							"path":       "security-team",
							"kind":       "group",
							"full_path":  "security-team",
							"parent_id":  nil,
							"avatar_url": "",
							"web_url":    serverURL(serverURLFromRequest(r), "/groups/security-team"),
						},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "enum-report.html")

	_, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "enum",
		"--url", server.URL,
		"--token", "glpat-test",
		"--report-html", htmlPath,
	}, nil, 10*time.Second)

	require.Nil(t, exitErr, "Enum command with export options should succeed")

	htmlContent, err := os.ReadFile(htmlPath)
	require.NoError(t, err)
	assert.Contains(t, string(htmlContent), "GitLab Enumeration Report")
	assert.Contains(t, string(htmlContent), "security-team / security-tools")

	t.Logf("STDERR:\n%s", stderr)
}

func TestGitLabEnum_WithUsersEnumeration(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       1,
				"username": "testuser",
				"name":     "Test User",
				"email":    "test@example.com",
			})
		case "/api/v4/groups/7/members/all", "/api/v4/projects/13/members/all":
			w.Header().Set("x-next-page", "")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":           2,
					"username":     "alice",
					"name":         "Alice Example",
					"email":        "alice@example.com",
					"public_email": "alice@example.com",
					"state":        "active",
					"web_url":      serverURL(serverURLFromRequest(r), "/alice"),
				},
			})
		case "/api/v4/personal_access_tokens/self":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":            99,
				"name":          "test-token",
				"revoked":       false,
				"created_at":    "2026-07-06T08:00:00Z",
				"description":   "e2e token",
				"scopes":        []string{"api", "read_api"},
				"user_id":       1,
				"last_used_at":  "2026-07-06T08:00:00Z",
				"active":        true,
				"expires_at":    "",
				"last_used_ips": []string{"127.0.0.1"},
			})
		case "/api/v4/personal_access_tokens/self/associations":
			w.Header().Set("x-next-page", "")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"groups": []map[string]interface{}{
					{
						"id":              7,
						"web_url":         serverURL(serverURLFromRequest(r), "/groups/security-team"),
						"name":            "security-team",
						"parent_id":       nil,
						"organization_id": 1,
						"access_levels":   50,
						"visibility":      "private",
					},
				},
				"projects": []map[string]interface{}{
					{
						"id":                  13,
						"description":         "",
						"name":                "security-tools",
						"name_with_namespace": "security-team / security-tools",
						"path":                "security-tools",
						"path_with_namespace": "security-team/security-tools",
						"created_at":          "2026-07-06T08:00:00Z",
						"access_levels": map[string]interface{}{
							"project_access_level": 0,
							"group_access_level":   50,
						},
						"visibility": "private",
						"web_url":    serverURL(serverURLFromRequest(r), "/security-team/security-tools"),
						"namespace": map[string]interface{}{
							"id":         7,
							"name":       "security-team",
							"path":       "security-team",
							"kind":       "group",
							"full_path":  "security-team",
							"parent_id":  nil,
							"avatar_url": "",
							"web_url":    serverURL(serverURLFromRequest(r), "/groups/security-team"),
						},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "enum-report-users.html")

	_, _, exitErr := testutil.RunCLI(t, []string{
		"gl", "enum",
		"--url", server.URL,
		"--token", "glpat-test",
		"--users",
		"--report-html", htmlPath,
	}, nil, 10*time.Second)

	require.Nil(t, exitErr, "Enum command with users enumeration should succeed")

	htmlContent, err := os.ReadFile(htmlPath)
	require.NoError(t, err)
	assert.Contains(t, string(htmlContent), "id=\"users-section\"")
	assert.Contains(t, string(htmlContent), "alice@example.com")
	assert.NotContains(t, string(htmlContent), "Member Endpoint")

	requests := getRequests()
	requestedGroupAllMembersEndpoint := false
	requestedProjectAllMembersEndpoint := false
	requestedGlobalUsersEndpoint := false
	for _, req := range requests {
		if req.Path == "/api/v4/groups/7/members/all" {
			requestedGroupAllMembersEndpoint = true
		}
		if req.Path == "/api/v4/projects/13/members/all" {
			requestedProjectAllMembersEndpoint = true
		}
		if req.Path == "/api/v4/users" {
			requestedGlobalUsersEndpoint = true
		}
	}
	assert.True(t, requestedGroupAllMembersEndpoint, "Expected group all_members endpoint request when --users is provided")
	assert.True(t, requestedProjectAllMembersEndpoint, "Expected project all_members endpoint request when --users is provided")
	assert.False(t, requestedGlobalUsersEndpoint, "Did not expect /api/v4/users request for scoped --users enumeration")
}

func serverURL(base string, suffix string) string {
	return base + suffix
}

func serverURLFromRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// TestGitLabVariables tests CI/CD variables extraction
