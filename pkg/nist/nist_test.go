package nist

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNVDServer creates a test HTTP server that simulates the NVD API
func mockNVDServer(_ *testing.T, totalVulns int, pageSize int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		// Parse pagination parameters
		resultsPerPage := pageSize
		if rpp := query.Get("resultsPerPage"); rpp != "" {
			_, _ = fmt.Sscanf(rpp, "%d", &resultsPerPage)
		}

		startIndex := 0
		if si := query.Get("startIndex"); si != "" {
			_, _ = fmt.Sscanf(si, "%d", &startIndex)
		}

		// Calculate how many results to return for this page
		remainingResults := totalVulns - startIndex
		if remainingResults < 0 {
			remainingResults = 0
		}
		if remainingResults > resultsPerPage {
			remainingResults = resultsPerPage
		}

		// Build mock vulnerabilities
		vulns := make([]json.RawMessage, remainingResults)
		for i := 0; i < remainingResults; i++ {
			cveID := fmt.Sprintf("CVE-2024-%05d", startIndex+i+1)
			vulns[i] = json.RawMessage(fmt.Sprintf(`{"cve":{"id":"%s","descriptions":[{"lang":"en","value":"Test vulnerability %d"}]}}`, cveID, startIndex+i+1))
		}

		// Build response
		response := nvdResponse{
			ResultsPerPage:  resultsPerPage,
			StartIndex:      startIndex,
			TotalResults:    totalVulns,
			Format:          "NVD_CVE",
			Version:         "2.0",
			Timestamp:       "2024-01-01T00:00:00.000",
			Vulnerabilities: vulns,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
}

func TestFetchVulns_NoPagination(t *testing.T) {
	// Create a mock server with 10 total vulnerabilities (fits in one page)
	server := mockNVDServer(t, 10, 100)
	defer server.Close()

	// Set the environment variable for the test
	t.Setenv("PIPELEEK_NIST_BASE_URL", server.URL)

	// Create a properly configured retryable client
	client := retryablehttp.NewClient()
	client.HTTPClient = server.Client()
	result, err := FetchVulns(client, "cpe:2.3:a:example:product:1.0.0:*:*:*:*:*:*:*")
	require.NoError(t, err)

	// Parse the result
	var response nvdResponse
	err = json.Unmarshal([]byte(result), &response)
	require.NoError(t, err)

	// Verify we got all vulnerabilities in one request
	assert.Equal(t, 10, response.TotalResults)
	assert.Equal(t, 10, len(response.Vulnerabilities))
	assert.Equal(t, 0, response.StartIndex)
}

func TestFetchVulns_WithPagination(t *testing.T) {
	// Create a mock server with 250 total vulnerabilities (requires pagination with pageSize=100)
	server := mockNVDServer(t, 250, 100)
	defer server.Close()

	// Set the environment variable for the test
	t.Setenv("PIPELEEK_NIST_BASE_URL", server.URL)

	client := retryablehttp.NewClient()
	client.HTTPClient = server.Client()
	result, err := FetchVulns(client, "cpe:2.3:a:example:product:1.0.0:*:*:*:*:*:*:*")
	require.NoError(t, err)

	// Parse the result
	var response nvdResponse
	err = json.Unmarshal([]byte(result), &response)
	require.NoError(t, err)

	// Verify all vulnerabilities were fetched
	assert.Equal(t, 250, response.TotalResults)
	assert.Equal(t, 250, len(response.Vulnerabilities))
	assert.Equal(t, 250, response.ResultsPerPage) // Updated to reflect actual count
	assert.Equal(t, 0, response.StartIndex)       // Reset to 0 in merged response

	// Verify unique CVE IDs (no duplicates from pagination)
	cveIDs := make(map[string]bool)
	for _, vuln := range response.Vulnerabilities {
		var v map[string]interface{}
		_ = json.Unmarshal(vuln, &v)
		cveID := v["cve"].(map[string]interface{})["id"].(string)
		assert.False(t, cveIDs[cveID], "Duplicate CVE ID: %s", cveID)
		cveIDs[cveID] = true
	}
	assert.Equal(t, 250, len(cveIDs))
}

func TestFetchVulns_EmptyResponse(t *testing.T) {
	server := mockNVDServer(t, 0, 100)
	defer server.Close()

	// Set the environment variable for the test
	t.Setenv("PIPELEEK_NIST_BASE_URL", server.URL)

	client := retryablehttp.NewClient()
	client.HTTPClient = server.Client()
	result, err := FetchVulns(client, "cpe:2.3:a:example:product:99.99.99:*:*:*:*:*:*:*")
	require.NoError(t, err)

	var response nvdResponse
	err = json.Unmarshal([]byte(result), &response)
	require.NoError(t, err)
	assert.Equal(t, 0, len(response.Vulnerabilities))
	assert.Equal(t, 0, response.TotalResults)
}

func TestFetchVulns_HTTPError(t *testing.T) {
	// Create a server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	// Set the environment variable for the test
	t.Setenv("PIPELEEK_NIST_BASE_URL", server.URL)

	client := retryablehttp.NewClient()
	client.HTTPClient = server.Client()
	client.RetryMax = 0 // Disable retries for faster test
	result, err := FetchVulns(client, "cpe:2.3:a:example:product:1.0.0:*:*:*:*:*:*:*")
	assert.Error(t, err)
	assert.Equal(t, "{}", result)
}

func TestFetchVulns_InvalidJSON(t *testing.T) {
	// Create a server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	// Set the environment variable for the test
	t.Setenv("PIPELEEK_NIST_BASE_URL", server.URL)

	client := retryablehttp.NewClient()
	client.HTTPClient = server.Client()
	result, err := FetchVulns(client, "cpe:2.3:a:example:product:1.0.0:*:*:*:*:*:*:*")
	assert.Error(t, err)
	assert.Equal(t, "{}", result)
}

func TestFetchVulns_LargePagination(t *testing.T) {
	// Test with a large number of vulnerabilities
	server := mockNVDServer(t, 1000, 100)
	defer server.Close()

	// Set the environment variable for the test
	t.Setenv("PIPELEEK_NIST_BASE_URL", server.URL)

	client := retryablehttp.NewClient()
	client.HTTPClient = server.Client()
	result, err := FetchVulns(client, "cpe:2.3:a:example:product:1.0.0:*:*:*:*:*:*:*")
	require.NoError(t, err)

	var response nvdResponse
	err = json.Unmarshal([]byte(result), &response)
	require.NoError(t, err)

	assert.Equal(t, 1000, response.TotalResults)
	assert.Equal(t, 1000, len(response.Vulnerabilities))

	// Verify CVEs are in order
	for i := 0; i < 1000; i++ {
		var v map[string]interface{}
		_ = json.Unmarshal(response.Vulnerabilities[i], &v)
		expectedCVE := fmt.Sprintf("CVE-2024-%05d", i+1)
		actualCVE := v["cve"].(map[string]interface{})["id"].(string)
		assert.Equal(t, expectedCVE, actualCVE)
	}
}

func TestFetchVulns_ExactPageBoundary(t *testing.T) {
	// Test with exactly 100 vulnerabilities (one full page)
	server := mockNVDServer(t, 100, 100)
	defer server.Close()

	// Set the environment variable for the test
	t.Setenv("PIPELEEK_NIST_BASE_URL", server.URL)

	client := retryablehttp.NewClient()
	client.HTTPClient = server.Client()
	result, err := FetchVulns(client, "cpe:2.3:a:example:product:1.0.0:*:*:*:*:*:*:*")
	require.NoError(t, err)

	var response nvdResponse
	err = json.Unmarshal([]byte(result), &response)
	require.NoError(t, err)

	assert.Equal(t, 100, response.TotalResults)
	assert.Equal(t, 100, len(response.Vulnerabilities))
}

func TestFetchVulns_MultiplePagesExactBoundary(t *testing.T) {
	// Test with exactly 200 vulnerabilities (two full pages)
	server := mockNVDServer(t, 200, 100)
	defer server.Close()

	// Set the environment variable for the test
	t.Setenv("PIPELEEK_NIST_BASE_URL", server.URL)

	client := retryablehttp.NewClient()
	client.HTTPClient = server.Client()
	result, err := FetchVulns(client, "cpe:2.3:a:example:product:1.0.0:*:*:*:*:*:*:*")
	require.NoError(t, err)

	var response nvdResponse
	err = json.Unmarshal([]byte(result), &response)
	require.NoError(t, err)

	assert.Equal(t, 200, response.TotalResults)
	assert.Equal(t, 200, len(response.Vulnerabilities))
}
