//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestCircleScan_ProjectHappyPath(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		baseURL := "http://" + r.Host

		switch {
		case r.URL.Path == "/api/v2/project/github/example-org/example-repo/pipeline":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{{
					"id":         "pipeline-1",
					"state":      "created",
					"created_at": "2026-01-10T10:00:00Z",
				}},
				"next_page_token": "",
			})
		case r.URL.Path == "/api/v2/pipeline/pipeline-1/workflow":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{{
					"id":         "wf-1",
					"name":       "build",
					"status":     "success",
					"created_at": "2026-01-10T10:05:00Z",
				}},
			})
		case r.URL.Path == "/api/v2/workflow/wf-1/job":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{{
					"job_number": 101,
					"name":       "unit-tests",
					"status":     "success",
				}},
			})
		case r.URL.Path == "/api/v2/project/github/example-org/example-repo/job/101":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"name":    "unit-tests",
				"web_url": fmt.Sprintf("%s/job/101", baseURL),
				"steps": []map[string]interface{}{{
					"actions": []map[string]interface{}{{
						"output_url": fmt.Sprintf("%s/log/101", baseURL),
					}},
				}},
			})
		case r.URL.Path == "/log/101":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("build started\nall good\n"))
		case r.URL.Path == "/api/v2/project/github/example-org/example-repo/101/tests":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{}})
		case r.URL.Path == "/api/v2/insights/github/example-org/example-repo/workflows":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []map[string]interface{}{{"name": "build"}}})
		case r.URL.Path == "/api/v2/insights/github/example-org/example-repo/workflows/build":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success_rate": 1.0})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"circle", "scan",
		"--circle", server.URL,
		"--token", "circle-token",
		"--project", "example-org/example-repo",
		"--max-pipelines", "1",
		"--tests", "false",
		"--insights", "false",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "circle scan should succeed")
	requests := getRequests()
	assert.True(t, len(requests) >= 5, "expected multiple CircleCI API requests")

	joined := stdout + stderr
	t.Logf("Output:\n%s", joined)
}

func TestCircleScan_OrgDiscovery(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v2/organization/example-org/project":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{{
					"slug": "github/example-org/example-repo",
				}},
				"next_page_token": "",
			})
		case r.URL.Path == "/api/v2/project/github/example-org/example-repo/pipeline":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{}, "next_page_token": ""})
		case strings.HasPrefix(r.URL.Path, "/api/v2/insights/github/example-org/example-repo/workflows"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	_, _, exitErr := testutil.RunCLI(t, []string{
		"circle", "scan",
		"--circle", server.URL,
		"--token", "circle-token",
		"--org", "example-org",
		"--max-pipelines", "1",
		"--tests", "false",
		"--insights", "false",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "circle scan should support org discovery without --project")

	requests := getRequests()
	sawOrgProjects := false
	for _, req := range requests {
		if req.Path == "/api/v2/organization/example-org/project" {
			sawOrgProjects = true
			break
		}
	}
	assert.True(t, sawOrgProjects, "expected org project discovery request")
}
