package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGitHubScan_Pagination_Check(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (Pagination): %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)

		switch r.URL.Path {
		case "/api/v3/user/repos":
			page := r.URL.Query().Get("page")

			switch page {
			case "", "1":
				// First page with Link header
				w.Header().Set("Link", `<http://`+r.Host+`/api/v3/user/repos?affiliation=owner&page=2&per_page=100>; rel="next", <http://`+r.Host+`/api/v3/user/repos?affiliation=owner&page=2&per_page=100>; rel="last"`)
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{
						"id":        1,
						"name":      "repo-1",
						"full_name": "user/repo-1",
						"html_url":  "https://github.com/user/repo-1",
						"owner":     map[string]interface{}{"login": "user"},
					},
				})
			case "2":
				// Second page - empty (end of pagination)
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
			default:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
			}

		case "/api/v3/repos/user/repo-1/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{},
				"total_count":   0,
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "scan",
		"--github", server.URL,
		"--token", "ghp_test_token",
		"--owned",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Pagination scan should succeed")

	requests := getRequests()
	// Dump recorded requests for debugging pagination
	t.Logf("Made %d requests", len(requests)) // Check if pagination happened (should have page 1 and page 2)
	testutil.DumpRequests(t, requests)
	hasPage1 := false
	hasPage2 := false
	for _, req := range requests {
		if req.Path == "/api/v3/user/repos" {
			query, _ := url.ParseQuery(req.RawQuery)
			page := query.Get("page")
			t.Logf("Request to repos with page=%s (query=%s)", page, req.RawQuery)
			if page == "" || page == "1" {
				hasPage1 = true
			}
			if page == "2" {
				hasPage2 = true
			}
		}
	}

	assert.True(t, hasPage1, "Should request page 1")
	assert.True(t, hasPage2, "Should request page 2")

	output := stdout + stderr
	assert.Contains(t, output, "Scan Finished", "Should complete scan")
	t.Logf("Output:\n%s", output)
}
