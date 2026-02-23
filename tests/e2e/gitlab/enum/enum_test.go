package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGitLabEnum(t *testing.T) {
	t.Parallel()
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
		"--gitlab", server.URL,
		"--token", "glpat-test",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Enum command should succeed")

	// Verify API calls
	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitLabVariables tests CI/CD variables extraction
