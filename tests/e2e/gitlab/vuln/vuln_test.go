//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func setupMockGitLabVulnAPI(t *testing.T) string {
	mux := http.NewServeMux()

	// Metadata endpoint (returns GitLab version)
	mux.HandleFunc("/api/v4/metadata", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"version":"15.10.0",
			"revision":"abc123",
			"kas":{"enabled":true,"version":"15.10.0"},
			"enterprise":false
		}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func setupMockNISTAPI(t *testing.T) string {
	mux := http.NewServeMux()

	// Mock NIST NVD API endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Return a mock response with test CVE data
		response := map[string]interface{}{
			"resultsPerPage": 2,
			"startIndex":     0,
			"totalResults":   2,
			"format":         "NVD_CVE",
			"version":        "2.0",
			"timestamp":      "2024-01-01T00:00:00.000",
			"vulnerabilities": []map[string]interface{}{
				{
					"cve": map[string]interface{}{
						"id": "CVE-2023-1234",
						"descriptions": []map[string]interface{}{
							{
								"lang":  "en",
								"value": "Test vulnerability 1 for GitLab 15.10.0",
							},
						},
					},
				},
				{
					"cve": map[string]interface{}{
						"id": "CVE-2023-5678",
						"descriptions": []map[string]interface{}{
							{
								"lang":  "en",
								"value": "Test vulnerability 2 for GitLab 15.10.0",
							},
						},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGLVuln(t *testing.T) {
	gitlabURL := setupMockGitLabVulnAPI(t)
	nistURL := setupMockNISTAPI(t)

	env := []string{
		"PIPELEEK_NIST_BASE_URL=" + nistURL,
	}

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "vuln",
		"--gitlab", gitlabURL,
		"--token", "mock-token",
	}, env, 15*time.Second)

	assert.Nil(t, exitErr, "Vuln command should succeed")
	assert.Contains(t, stdout, "15.10.0", "Should show GitLab version")
	assert.Contains(t, stdout, "CVE-2023-1234", "Should show mock CVE from NIST")
	assert.Contains(t, stdout, "CVE-2023-5678", "Should show second mock CVE from NIST")
	assert.Contains(t, stdout, "Finished vuln scan", "Should complete vuln scan")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLVuln_MissingToken(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "vuln",
		"--gitlab", "https://gitlab.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token")
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing", "Should mention missing required configuration")
}

func TestGLVuln_MissingGitLabURL(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "vuln",
		"--token", "test-token",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without gitlab URL")
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing", "Should mention missing required configuration")
}

func TestGLVuln_Unauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/metadata", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"401 Unauthorized"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	nistURL := setupMockNISTAPI(t)
	env := []string{
		"PIPELEEK_NIST_BASE_URL=" + nistURL,
	}

	stdout, _, _ := testutil.RunCLI(t, []string{
		"gl", "vuln",
		"--gitlab", server.URL,
		"--token", "invalid-token",
	}, env, 10*time.Second)

	// Vuln command checks NIST database regardless of auth failure
	assert.Contains(t, stdout, "Finished vuln scan", "Should complete vulnerability scan")
}
