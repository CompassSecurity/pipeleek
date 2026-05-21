//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabUsersEnum(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path != "/api/v4/users" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}

		switch r.URL.Query().Get("page") {
		case "", "1":
			w.Header().Set("X-Next-Page", "2")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":           1,
				"username":     "alice",
				"name":         "Alice Example",
				"public_email": "alice@example.com",
				"web_url":      "http://" + r.Host + "/alice",
				"state":        "active",
			}})
		case "2":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":       2,
				"username": "bob",
				"name":     "Bob Example",
				"web_url":  "http://" + r.Host + "/bob",
				"state":    "blocked",
				"bot":      true,
			}})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "users", "enum",
		"--url", server.URL,
		"--token", "glpat-test",
	}, nil, 30*time.Second)

	require.NoError(t, exitErr)

	requests := getRequests()
	require.Len(t, requests, 2)
	assert.Equal(t, "/api/v4/users", requests[0].Path)
	assert.Equal(t, "glpat-test", requests[0].Headers.Get("PRIVATE-TOKEN"))
	assert.Contains(t, requests[0].RawQuery, "page=1")
	assert.Contains(t, requests[1].RawQuery, "page=2")

	assert.Contains(t, stdout, "Enumerating GitLab users")
	assert.Contains(t, stdout, "User")
	assert.Contains(t, stdout, "alice")
	assert.Contains(t, stdout, "bob")
	assert.Contains(t, stdout, "GitLab user enumeration complete")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

func TestGitLabUsersEnumUnauthenticatedFallback(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/users":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "401 Unauthorized"})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":      11,
				"name":    "public-group",
				"web_url": "http://" + r.Host + "/groups/public-group",
			}})
		case "/api/v4/groups/11/members", "/api/v4/groups/11/members/all":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":           1,
				"username":     "alice",
				"name":         "Alice Example",
				"public_email": "alice@example.com",
				"web_url":      "http://" + r.Host + "/alice",
				"state":        "active",
			}})
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":                  22,
				"name":                "public-project",
				"path_with_namespace": "public-group/public-project",
				"web_url":             "http://" + r.Host + "/public-group/public-project",
			}})
		case "/api/v4/projects/22/members", "/api/v4/projects/22/members/all":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":       1,
					"username": "alice",
					"name":     "Alice Example",
					"web_url":  "http://" + r.Host + "/alice",
					"state":    "active",
				},
				{
					"id":       2,
					"username": "bob",
					"name":     "Bob Example",
					"web_url":  "http://" + r.Host + "/bob",
					"state":    "blocked",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "users", "enum",
		"--url", server.URL,
	}, nil, 15*time.Second)

	require.NoError(t, exitErr)

	requests := getRequests()
	require.Len(t, requests, 5)
	assert.Equal(t, "/api/v4/users", requests[0].Path)
	assert.Empty(t, requests[0].Headers.Get("PRIVATE-TOKEN"))
	assert.Contains(t, requests[0].RawQuery, "page=1")
	assert.Equal(t, "/api/v4/groups", requests[1].Path)
	assert.Contains(t, requests[1].RawQuery, "visibility=public")
	assert.Equal(t, "/api/v4/groups/11/members/all", requests[2].Path)
	assert.Equal(t, "/api/v4/projects", requests[3].Path)
	assert.Contains(t, requests[3].RawQuery, "visibility=public")
	assert.Contains(t, requests[3].RawQuery, "simple=true")
	assert.Equal(t, "/api/v4/projects/22/members/all", requests[4].Path)

	combinedOutput := stdout + stderr
	assert.Contains(t, combinedOutput, "Enumerating GitLab users")
	assert.Contains(t, combinedOutput, "alice")
	assert.Contains(t, combinedOutput, "bob")
	assert.Contains(t, combinedOutput, "public_group_members")
	assert.Contains(t, combinedOutput, "public_project_members")
	assert.Contains(t, combinedOutput, "GitLab user enumeration complete")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

func TestGitLabUsersEnumUnauthenticatedRejected(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/users", "/api/v4/groups", "/api/v4/projects":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "401 Unauthorized"})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "users", "enum",
		"--url", server.URL,
	}, nil, 15*time.Second)

	require.Error(t, exitErr)

	requests := getRequests()
	require.Len(t, requests, 3)
	assert.Equal(t, "/api/v4/users", requests[0].Path)
	assert.Equal(t, "/api/v4/groups", requests[1].Path)
	assert.Equal(t, "/api/v4/projects", requests[2].Path)

	combinedOutput := stdout + stderr
	assert.Contains(t, combinedOutput, "Enumerating GitLab users")
	assert.Contains(t, combinedOutput, "Anonymous GitLab user enumeration is not supported by this instance")
	assert.Contains(t, combinedOutput, "use a token for full user enumeration")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}
