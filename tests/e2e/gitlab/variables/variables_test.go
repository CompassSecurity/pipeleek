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

func setupMockGitLabVariablesAPI(t *testing.T) string {
	mux := http.NewServeMux()

	// Projects list endpoint
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"id":123,"name":"test-project","web_url":"https://gitlab.com/test-project"}
		]`))
	})

	// Project variables endpoint
	mux.HandleFunc("/api/v4/projects/123/variables", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"key":"DATABASE_URL","value":"postgres://localhost","protected":true,"masked":true},
			{"key":"API_KEY","value":"secret123","protected":false,"masked":true}
		]`))
	})

	// Groups list endpoint
	mux.HandleFunc("/api/v4/groups", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"id":456,"name":"test-group","web_url":"https://gitlab.com/test-group"}
		]`))
	})

	// Group variables endpoint
	mux.HandleFunc("/api/v4/groups/456/variables", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"key":"GROUP_VAR","value":"group-value","protected":false,"masked":false}
		]`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGLVariables(t *testing.T) {
	apiURL := setupMockGitLabVariablesAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "variables",
		"--gitlab", apiURL,
		"--token", "mock-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Variables command should succeed")
	assert.Contains(t, stdout, "DATABASE_URL", "Should show project variable key")
	assert.Contains(t, stdout, "API_KEY", "Should show project variable key")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLVariables_MissingToken(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "variables",
		"--gitlab", "https://gitlab.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token")
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing", "Should mention missing required configuration")
}

func TestGLVariables_Unauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"401 Unauthorized"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"gl", "variables",
		"--gitlab", server.URL,
		"--token", "invalid-token",
	}, nil, 10*time.Second)

	// Command may handle errors gracefully
	assert.Contains(t, stdout+stderr, "401", "Should indicate unauthorized")
}
