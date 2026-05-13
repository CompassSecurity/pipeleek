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
		"--gitlab", server.URL,
		"--token", "glpat-test",
	}, nil, 15*time.Second)

	require.NoError(t, exitErr)

	requests := getRequests()
	require.Len(t, requests, 2)
	assert.Equal(t, "/api/v4/users", requests[0].Path)
	assert.Equal(t, "glpat-test", requests[0].Headers.Get("PRIVATE-TOKEN"))
	assert.Contains(t, requests[0].RawQuery, "page=1")
	assert.Contains(t, requests[1].RawQuery, "page=2")

	assert.Contains(t, stdout, "Enumerating GitLab users")
	assert.Contains(t, stdout, "GitLab user")
	assert.Contains(t, stdout, "alice")
	assert.Contains(t, stdout, "bob")
	assert.Contains(t, stdout, "GitLab user enumeration complete")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}
