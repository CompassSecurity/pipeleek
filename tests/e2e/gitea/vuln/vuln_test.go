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

func setupMockGiteaVulnAPI(t *testing.T) string {
	mux := http.NewServeMux()

	// Gitea version endpoint
	mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":"1.20.0"}`))
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
								"value": "Test vulnerability 1 for Gitea 1.20.0",
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
								"value": "Test vulnerability 2 for Gitea 1.20.0",
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

func TestGiteaVuln(t *testing.T) {
	giteaURL := setupMockGiteaVulnAPI(t)
	nistURL := setupMockNISTAPI(t)

	env := []string{
		"PIPELEEK_NIST_BASE_URL=" + nistURL,
	}

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "vuln",
		"--gitea", giteaURL,
		"--token", "mock-token",
	}, env, 15*time.Second)

	assert.Nil(t, exitErr, "Vuln command should succeed")
	assert.Contains(t, stdout, "1.20.0", "Should show Gitea version")
	assert.Contains(t, stdout, "CVE-2023-1234", "Should show mock CVE from NIST")
	assert.Contains(t, stdout, "CVE-2023-5678", "Should show second mock CVE from NIST")
	assert.Contains(t, stdout, "Finished vuln scan", "Should complete vuln scan")
	assert.NotContains(t, stderr, "fatal")
}

func TestGiteaVuln_MissingToken(t *testing.T) {
	_, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "vuln",
		"--gitea", "https://gitea.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token")
	assert.Contains(t, stderr, "required flag(s)", "Should mention missing required flag")
}

func TestGiteaVuln_MissingGitea(t *testing.T) {
	_, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "vuln",
		"--token", "mock-token",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without gitea URL")
	assert.Contains(t, stderr, "required flag(s)", "Should mention missing required flag")
}

func TestGiteaVuln_Unauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
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
		"gitea", "vuln",
		"--gitea", server.URL,
		"--token", "invalid-token",
	}, env, 10*time.Second)

	// Vuln command checks NIST database regardless of auth failure
	assert.Contains(t, stdout, "Finished vuln scan", "Should complete vulnerability scan")
}
