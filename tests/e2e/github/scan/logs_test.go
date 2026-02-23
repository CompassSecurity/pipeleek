package e2e

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGitHubScan_HappyPath(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		t.Logf("GitHub Mock: %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/api/v3/user/repos":
			w.WriteHeader(http.StatusOK)
			// GitHub API returns an array directly, not wrapped in an object
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        1,
					"name":      "test-repo",
					"full_name": "user/test-repo",
					"html_url":  "https://github.com/user/test-repo",
					"owner":     map[string]interface{}{"login": "user"},
				},
			})

		case "/api/v3/repos/user/test-repo/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{
						"id":            100,
						"name":          "test-workflow",
						"status":        "completed",
						"display_title": "Test Workflow Run",
						"html_url":      "https://github.com/user/test-repo/actions/runs/100",
						"repository": map[string]interface{}{
							"name":  "test-repo",
							"owner": map[string]interface{}{"login": "user"},
						},
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/100/logs":
			// Return 302 redirect
			w.Header().Set("Location", "http://"+r.Host+"/download/logs/100.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/logs/100.zip":
			// Create zipped logs (empty)
			var logsZip bytes.Buffer
			zw := zip.NewWriter(&logsZip)
			lf, _ := zw.Create("job.log")
			_, _ = lf.Write([]byte("Build completed\n"))
			_ = zw.Close()
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(logsZip.Bytes())

		case "/api/v3/repos/user/test-repo/actions/runs/100/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jobs": []map[string]interface{}{
					{"id": 1000, "name": "test-job"},
				},
				"total_count": 1,
			})

		default:
			t.Logf("Unmocked path: %s", r.URL.Path)
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
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "GitHub scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	// Verify Authorization header
	for _, req := range requests {
		authHeader := req.Headers.Get("Authorization")
		if authHeader != "" {
			assert.Contains(t, authHeader, "token", "Should use token authentication")
		}
	}

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitHubScan_MissingToken tests missing required flags

func TestGitHubScan_WithLogs(t *testing.T) {
	t.Parallel()
	// prepare zipped logs (single file inside ZIP)
	var logsZip bytes.Buffer
	zw := zip.NewWriter(&logsZip)
	lf, _ := zw.Create("log.txt")
	logContent := `2023-01-01T10:00:00.0000000Z ##[group]Run actions/checkout@v3
2023-01-01T10:00:06.0000000Z export DATABASE_URL=postgresql://admin:superSecretP@ssw0rd123@db.example.com:5432/prod_db
2023-01-01T10:00:07.0000000Z export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
2023-01-01T10:00:08.0000000Z export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
2023-01-01T10:00:09.0000000Z export STRIPE_SECRET_KEY=sk_live_51H8example123456789
2023-01-01T10:00:10.0000000Z export GITHUB_TOKEN=ghp_examplePersonalAccessToken123456789
`
	_, _ = lf.Write([]byte(logContent))
	_ = zw.Close()

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock: %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/api/v3/user/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        1,
					"name":      "test-repo",
					"full_name": "user/test-repo",
					"html_url":  "https://github.com/user/test-repo",
					"owner":     map[string]interface{}{"login": "user"},
				},
			})

		case "/api/v3/repos/user/test-repo/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{
						"id":            100,
						"status":        "completed",
						"display_title": "CI Build",
						"html_url":      "https://github.com/user/test-repo/actions/runs/100",
						"repository": map[string]interface{}{
							"name":  "test-repo",
							"owner": map[string]interface{}{"login": "user"},
						},
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/100/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jobs": []map[string]interface{}{
					{
						"id":     1000,
						"name":   "build",
						"status": "completed",
					},
				},
				"total_count": 1,
			})

		// SDK calls GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs and expects a redirect to
		// the archive URL. Return a 302 redirect to a downloadable zip.
		case "/api/v3/repos/user/test-repo/actions/runs/100/logs":
			w.Header().Set("Location", "http://"+r.Host+"/download/logs/100.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/logs/100.zip":
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(logsZip.Bytes())

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

	assert.Nil(t, exitErr, "GitHub scan with logs should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 3, "Should make multiple API requests")

	output := stdout + stderr
	assert.Contains(t, output, "SECRET", "Should detect secrets in logs")
	assert.Contains(t, output, "Password in URL", "Should detect database password")
	t.Logf("Output:\n%s", output)
}

// TestGitHubScan_Artifacts_WithDotEnv tests scanning artifacts with .env files
