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

func TestGitLabUnauthenticatedUsersEnum(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path != "/api/v4/users" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":       7,
			"username": "public-user",
			"name":     "Public User",
			"web_url":  "http://" + r.Host + "/public-user",
			"state":    "active",
		}})
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "users", "enum",
		"--gitlab", server.URL,
	}, nil, 15*time.Second)

	require.NoError(t, exitErr)

	requests := getRequests()
	require.Len(t, requests, 1)
	assert.Equal(t, "/api/v4/users", requests[0].Path)
	assert.Empty(t, requests[0].Headers.Get("PRIVATE-TOKEN"))
	assert.Contains(t, stdout, "GitLab user")
	assert.Contains(t, stdout, "public-user")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}
