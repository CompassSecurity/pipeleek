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

func setupMockGitLabSecureFilesAPI(t *testing.T) string {
	mux := http.NewServeMux()

	// Projects list endpoint
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"id":123,"name":"test-project","web_url":"https://gitlab.com/test-project"}
		]`))
	})

	// Secure files endpoint
	mux.HandleFunc("/api/v4/projects/123/secure_files", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{
				"id":1,
				"name":"certificate.pem",
				"checksum":"abc123def456",
				"created_at":"2023-01-01T00:00:00Z"
			},
			{
				"id":2,
				"name":"keyfile.key",
				"checksum":"789xyz012",
				"created_at":"2023-01-02T00:00:00Z"
			}
		]`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGLSecureFiles(t *testing.T) {
	apiURL := setupMockGitLabSecureFilesAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "secureFiles",
		"--gitlab", apiURL,
		"--token", "mock-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Secure files command should succeed")
	assert.Contains(t, stdout, "Fetched all secure files", "Should complete fetching secure files")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLSecureFiles_MissingToken(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "secureFiles",
		"--gitlab", "https://gitlab.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token")
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing", "Should mention missing required configuration")
}

func TestGLSecureFiles_MissingGitLabURL(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "secureFiles",
		"--token", "test-token",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without gitlab URL")
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing", "Should mention missing required configuration")
}

func TestGLSecureFiles_Unauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"401 Unauthorized"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"gl", "secureFiles",
		"--gitlab", server.URL,
		"--token", "invalid-token",
	}, nil, 10*time.Second)

	// Command may handle errors gracefully
	assert.Contains(t, stdout+stderr, "401", "Should indicate unauthorized")
}
