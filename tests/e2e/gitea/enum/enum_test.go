package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGiteaEnum(t *testing.T) {

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		case "/api/v1/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":        1,
				"login":     "testuser",
				"email":     "test@example.com",
				"full_name": "Test User",
			})

		case "/api/v1/user/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        1,
					"name":      "repo1",
					"full_name": "testuser/repo1",
					"owner":     map[string]interface{}{"username": "testuser"},
				},
				{
					"id":        2,
					"name":      "repo2",
					"full_name": "testuser/repo2",
					"owner":     map[string]interface{}{"username": "testuser"},
				},
			})

		case "/api/v1/user/orgs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 10, "name": "my-org", "username": "my-org"},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	for _, mode := range []string{"direct", "explicit proxy"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"gitea", "enum", "--token", "gitea-token"}
			if mode == "explicit proxy" {
				args = append(args, "--url", "http://gitea.invalid", "--proxy", server.URL, "--ignore-proxy")
			} else {
				args = append(args, "--url", server.URL)
			}
			before := len(getRequests())
			stdout, stderr, exitErr := testutil.RunCLI(t, args, nil, 10*time.Second)

			assert.Nil(t, exitErr, "Enum command should succeed")
			assert.Greater(t, len(getRequests()), before, "Should make API requests")
			output := stdout + stderr
			assert.Contains(t, output, "testuser")
			assert.Contains(t, output, "repo1")
			assert.Contains(t, output, "repo2")
			assert.Contains(t, output, "my-org")
		})
	}
}

// TestGitea_APIErrors tests various API error responses
