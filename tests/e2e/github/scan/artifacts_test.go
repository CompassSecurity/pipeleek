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

func TestGitHubScan_Artifacts_WithDotEnv(t *testing.T) {
	t.Parallel()
	// Create artifact zip with a .env file
	var artifactZipBuf bytes.Buffer
	artifactZipWriter := zip.NewWriter(&artifactZipBuf)

	envFile, _ := artifactZipWriter.Create(".env")
	envContent := `# Production Environment
DATABASE_URL=postgresql://admin:superSecretP@ssw0rd123@db.example.com:5432/prod_db
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51H8example123456789
GITHUB_TOKEN=ghp_examplePersonalAccessToken123456789
API_KEY=sk_test_abcdefghijklmnopqrstuvwxyz123456
`
	_, _ = envFile.Write([]byte(envContent))
	_ = artifactZipWriter.Close()

	// Create logs zip (empty/benign logs)
	var logsZipBuf bytes.Buffer
	logsZipWriter := zip.NewWriter(&logsZipBuf)
	logFile, _ := logsZipWriter.Create("job.log")
	_, _ = logFile.Write([]byte("2023-01-01T10:00:00.0000000Z Starting build...\n2023-01-01T10:00:01.0000000Z Build completed successfully\n"))
	_ = logsZipWriter.Close()

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (Artifacts): %s %s", r.Method, r.URL.Path)

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
						"id":            200,
						"name":          "build-workflow",
						"status":        "completed",
						"display_title": "Build with Artifacts",
						"html_url":      "https://github.com/user/test-repo/actions/runs/200",
						"repository": map[string]interface{}{
							"name":  "test-repo",
							"owner": map[string]interface{}{"login": "user"},
						},
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/200/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jobs": []map[string]interface{}{
					{
						"id":     2000,
						"name":   "artifact-build",
						"status": "completed",
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/200/logs":
			w.Header().Set("Location", "http://"+r.Host+"/download/logs/200.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/logs/200.zip":
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(logsZipBuf.Bytes())

		case "/api/v3/repos/user/test-repo/actions/runs/200/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"artifacts": []map[string]interface{}{
					{
						"id":                   1,
						"name":                 "build-output",
						"archive_download_url": "http://" + r.Host + "/api/v3/repos/user/test-repo/actions/artifacts/1/zip",
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/artifacts/1/zip":
			// Return a redirect (302) to the actual download URL - the SDK expects this behavior
			w.Header().Set("Location", "http://"+r.Host+"/download/artifacts/1.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/artifacts/1.zip":
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(artifactZipBuf.Bytes())

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
		"--artifacts",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "Artifact scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 4, "Should make API requests including artifact download")

	output := stdout + stderr
	assert.Contains(t, output, "SECRET", "Should detect secrets in artifact")
	assert.Contains(t, output, ".env", "Should detect .env file")
	assert.Contains(t, output, "Password in URL", "Should detect database password")
	t.Logf("Output:\n%s", output)
}

// TestGitHubScan_MaxArtifactSize tests the --max-artifact-size flag for GitHub
func TestGitHubScan_Artifacts_MaxArtifactSize(t *testing.T) {
	t.Parallel()
	// Create small artifact (100KB) with secrets
	var smallArtifactBuf bytes.Buffer
	smallZipWriter := zip.NewWriter(&smallArtifactBuf)
	smallFile, _ := smallZipWriter.Create("config.env")
	_, _ = smallFile.Write([]byte(`DATABASE_PASSWORD=SuperSecret123!
API_KEY=test_key_1234567890abcdefghijklmnopqrstuvwxyz
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`))
	_ = smallZipWriter.Close()

	// Create large artifact (100MB simulation - just metadata)
	var largeArtifactBuf bytes.Buffer
	largeZipWriter := zip.NewWriter(&largeArtifactBuf)
	largeFile, _ := largeZipWriter.Create("large.txt")
	_, _ = largeFile.Write([]byte("This would be large"))
	_ = largeZipWriter.Close()

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (MaxArtifactSize): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/api/v3/user/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        1,
					"name":      "artifact-test",
					"full_name": "user/artifact-test",
					"html_url":  "https://github.com/user/artifact-test",
					"owner":     map[string]interface{}{"login": "user"},
				},
			})

		case "/api/v3/repos/user/artifact-test/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{
						"id":            100,
						"name":          "test-workflow",
						"status":        "completed",
						"display_title": "Test Artifacts",
						"html_url":      "https://github.com/user/artifact-test/actions/runs/100",
						"repository": map[string]interface{}{
							"name":  "artifact-test",
							"owner": map[string]interface{}{"login": "user"},
						},
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/artifact-test/actions/runs/100/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jobs":        []map[string]interface{}{},
				"total_count": 0,
			})

		case "/api/v3/repos/user/artifact-test/actions/runs/100/logs":
			w.Header().Set("Location", "http://"+r.Host+"/download/logs/100.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/logs/100.zip":
			w.WriteHeader(http.StatusNotFound)

		case "/api/v3/repos/user/artifact-test/actions/runs/100/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"artifacts": []map[string]interface{}{
					{
						"id":                   1001,
						"name":                 "large-artifact",
						"size_in_bytes":        100 * 1024 * 1024, // 100MB
						"archive_download_url": "http://" + r.Host + "/api/v3/repos/user/artifact-test/actions/artifacts/1001/zip",
					},
					{
						"id":                   1002,
						"name":                 "small-artifact",
						"size_in_bytes":        100 * 1024, // 100KB
						"archive_download_url": "http://" + r.Host + "/api/v3/repos/user/artifact-test/actions/artifacts/1002/zip",
					},
				},
				"total_count": 2,
			})

		case "/api/v3/repos/user/artifact-test/actions/artifacts/1001/zip":
			// Large artifact - should NOT be called if size checking works
			t.Error("Large artifact download should be skipped before SDK call")
			w.Header().Set("Location", "http://"+r.Host+"/download/artifact/1001")
			w.WriteHeader(http.StatusFound)

		case "/api/v3/repos/user/artifact-test/actions/artifacts/1002/zip":
			// Small artifact - should be downloaded
			w.Header().Set("Location", "http://"+r.Host+"/download/artifact/1002")
			w.WriteHeader(http.StatusFound)

		case "/download/artifact/1001":
			// This should not be called if size checking works
			t.Error("Large artifact should not be downloaded")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(largeArtifactBuf.Bytes())

		case "/download/artifact/1002":
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(smallArtifactBuf.Bytes())

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
		"--artifacts",
		"--max-artifact-size", "50Mb", // Only scan artifacts < 50MB
		"--owned",
		"--log-level", "debug", // Enable debug logs to see size checking
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "GitHub artifact scan with max-artifact-size should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify that large artifact was skipped (logged at debug level)
	assert.Contains(t, output, "Skipped large artifact", "Should log skipping of large artifact")
	assert.Contains(t, output, "large-artifact", "Should mention large artifact name in skip message")

	// Verify that small artifact was downloaded and scanned successfully
	assert.Contains(t, output, "small-artifact", "Should process small artifact")
	assert.Contains(t, output, "SECRET", "Should detect secrets in small artifact")
	assert.Contains(t, output, "config.env", "Should scan config.env file in small artifact")

	// Verify SDK call was not made for large artifact
	requests := getRequests()
	var largeArtifactSDKCalls []testutil.RecordedRequest
	for _, req := range requests {
		if req.Path == "/api/v3/repos/user/artifact-test/actions/artifacts/1001/zip" {
			largeArtifactSDKCalls = append(largeArtifactSDKCalls, req)
		}
	}
	assert.Equal(t, 0, len(largeArtifactSDKCalls), "Large artifact SDK call should not be made")
}

// TestGitHubScan_Artifacts_NestedArchive tests nested zip handling

func TestGitHubScan_Artifacts_NestedArchive(t *testing.T) {
	t.Parallel()
	// Create inner zip with secret
	var innerZipBuf bytes.Buffer
	innerZipWriter := zip.NewWriter(&innerZipBuf)
	secretFile, _ := innerZipWriter.Create("config/secret.txt")
	_, _ = secretFile.Write([]byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAPI_TOKEN=ghp_secretTokenValue123456789"))
	_ = innerZipWriter.Close()

	// Create outer zip containing inner zip
	var outerZipBuf bytes.Buffer
	outerZipWriter := zip.NewWriter(&outerZipBuf)
	innerZipFile, _ := outerZipWriter.Create("nested/inner.zip")
	_, _ = innerZipFile.Write(innerZipBuf.Bytes())
	_ = outerZipWriter.Close()

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (Nested): %s %s", r.Method, r.URL.Path)

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
						"id":            300,
						"name":          "nested-workflow",
						"status":        "completed",
						"display_title": "Nested Archive Build",
						"html_url":      "https://github.com/user/test-repo/actions/runs/300",
						"repository": map[string]interface{}{
							"name":  "test-repo",
							"owner": map[string]interface{}{"login": "user"},
						},
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/300/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jobs": []map[string]interface{}{
					{
						"id":     3000,
						"name":   "nested-build",
						"status": "completed",
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/300/logs":
			// Return 302 redirect like other tests
			w.Header().Set("Location", "http://"+r.Host+"/download/logs/300.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/logs/300.zip":
			// Return empty zip for logs (no secrets in logs for this test)
			var emptyZip bytes.Buffer
			zw := zip.NewWriter(&emptyZip)
			lf, _ := zw.Create("job.log")
			_, _ = lf.Write([]byte("No secrets in logs\n"))
			_ = zw.Close()
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(emptyZip.Bytes())

		case "/api/v3/repos/user/test-repo/actions/runs/300/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"artifacts": []map[string]interface{}{
					{
						"id":                   2,
						"name":                 "nested-artifact",
						"archive_download_url": "http://" + r.Host + "/api/v3/repos/user/test-repo/actions/artifacts/2/zip",
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/artifacts/2/zip":
			// Return 302 redirect like other artifact endpoints
			w.Header().Set("Location", "http://"+r.Host+"/download/artifacts/2.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/artifacts/2.zip":
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(outerZipBuf.Bytes())

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
		"--artifacts",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "Nested artifact scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 4, "Should make API requests")

	output := stdout + stderr
	assert.Contains(t, output, "SECRET", "Should detect secrets in nested archive")
	assert.Contains(t, output, "secret.txt", "Should detect secret.txt file")
	t.Logf("Output:\n%s", output)
}

// TestGitHubScan_Organization tests scanning organization repositories
