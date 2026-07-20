//go:build e2e

package e2e

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func setupMockGitLabWhoAmIAPI(t *testing.T) string {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":42,"username":"alice","name":"Alice Example","email":"alice@example.com","is_admin":false,"bot":false}`))
	})
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":99,"name":"ci-token","revoked":false,"created_at":"2025-01-01T00:00:00Z","description":"for tests","scopes":["api","read_api"],"user_id":42,"active":true,"expires_at":"2027-01-01","last_used_ips":["10.0.0.1"]}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGLWhoAmI(t *testing.T) {
	apiURL := setupMockGitLabWhoAmIAPI(t)

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "whoami",
		"--url", apiURL,
		"--token", "glpat-test",
	}, nil, 120*time.Second)

	assert.Nil(t, exitErr, "whoami command should succeed")
	assert.Contains(t, stdout, "Current user", "Should print current user summary")
	assert.Contains(t, stdout, "alice", "Should include current username")
	assert.Contains(t, stdout, "Current token", "Should print current token summary")
	assert.Contains(t, stdout, "ci-token", "Should include current token name")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLWhoAmI_MissingToken(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "whoami",
		"--url", "https://gitlab.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token")
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing", "Should mention missing required configuration")
}
