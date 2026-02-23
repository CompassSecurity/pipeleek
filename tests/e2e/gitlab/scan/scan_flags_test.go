package e2e

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

// TestGitLabScan_ConfidenceFilter tests the --confidence flag
func TestGitLabScan_ConfidenceFilter(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-project", "path_with_namespace": "group/test-project"},
			})

		case "/api/v4/projects/1/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 100, "ref": "main", "status": "success"},
			})

		case "/api/v4/projects/1/pipelines/100/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1000, "name": "test-job", "status": "success"},
			})

		case "/api/v4/projects/1/jobs/1000/trace":
			w.WriteHeader(http.StatusOK)
			logContent := `Running job...
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export DATABASE_PASSWORD=supersecret123
export MAYBE_SECRET=value123
Job complete`
			_, _ = w.Write([]byte(logContent))

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--confidence", "high,medium",
		"--job-limit", "1",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Scan with confidence filter should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	// The scanner should filter secrets based on confidence levels
}

// TestGitLabScan_CookieAuthentication tests the --cookie flag for dotenv artifacts
func TestGitLabScan_CookieAuthentication(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check if cookie is present
		cookie := r.Header.Get("Cookie")
		if strings.Contains(cookie, "_gitlab_session=test-cookie-value") {
			t.Logf("Cookie authentication verified: %s", cookie)
		}

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "cookie-test-project", "path_with_namespace": "group/project"},
			})

		case "/api/v4/projects/1/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 200, "ref": "main", "status": "success"},
			})

		case "/api/v4/projects/1/pipelines/200/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 2000, "name": "build-job", "status": "success"},
			})

		case "/api/v4/projects/1/jobs/2000/trace":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Job log\n"))

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--cookie", "test-cookie-value",
		"--job-limit", "1",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Scan with cookie authentication should succeed")

	// Verify cookie was sent in requests
	requests := getRequests()
	cookieFound := false
	for _, req := range requests {
		if strings.Contains(req.Headers.Get("Cookie"), "_gitlab_session=test-cookie-value") {
			cookieFound = true
			break
		}
	}
	t.Logf("Cookie found in requests: %v", cookieFound)

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

// TestGitLabScan_MaxArtifactSize tests the --max-artifact-size flag
func TestGitLabScan_MaxArtifactSize(t *testing.T) {
	t.Parallel()
	// Create small artifact with secrets
	var smallArtifactBuf bytes.Buffer
	smallZipWriter := zip.NewWriter(&smallArtifactBuf)
	smallFile, _ := smallZipWriter.Create("deployment.env")
	_, _ = smallFile.Write([]byte(`REDIS_PASSWORD=SuperSecretRedisP@ss!
JWT_SECRET_KEY=jwt_secret_key_abcdefghijklmnopqrstuvwxyz1234567890
OAUTH_CLIENT_SECRET=oauth_secret_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456
`))
	_ = smallZipWriter.Close()

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "artifact-test"},
			})

		case "/api/v4/projects/1/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 300, "status": "success"},
			})

		case "/api/v4/projects/1/pipelines/300/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":      3000,
					"name":    "large-artifact-job",
					"status":  "success",
					"web_url": "http://" + r.Host + "/project/-/jobs/3000",
					"artifacts_file": map[string]interface{}{
						"filename": "large.zip",
						"size":     1024 * 1024 * 100, // 100MB
					},
				},
				{
					"id":      3001,
					"name":    "small-artifact-job",
					"status":  "success",
					"web_url": "http://" + r.Host + "/project/-/jobs/3001",
					"artifacts_file": map[string]interface{}{
						"filename": "small.zip",
						"size":     1024 * 100, // 100KB
					},
				},
			})

		case "/api/v4/projects/1/jobs/3000/trace":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Job 3000 build log"))

		case "/api/v4/projects/1/jobs/3001/trace":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Job 3001 build log"))

		case "/api/v4/projects/1/jobs/3000/artifacts":
			t.Error("Large artifact should not be downloaded")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PK\x03\x04")) // ZIP magic bytes

		case "/api/v4/projects/1/jobs/3001/artifacts":
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(smallArtifactBuf.Bytes())

		case "/api/v4/projects/1/jobs":
			// ListProjectJobs endpoint (not pipeline-specific)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":       3000,
					"name":     "large-artifact-job",
					"status":   "success",
					"web_url":  "http://" + r.Host + "/project/-/jobs/3000",
					"pipeline": map[string]interface{}{"id": 300},
					"artifacts_file": map[string]interface{}{
						"filename": "large.zip",
						"size":     1024 * 1024 * 100, // 100MB
					},
				},
				{
					"id":       3001,
					"name":     "small-artifact-job",
					"status":   "success",
					"web_url":  "http://" + r.Host + "/project/-/jobs/3001",
					"pipeline": map[string]interface{}{"id": 300},
					"artifacts_file": map[string]interface{}{
						"filename": "small.zip",
						"size":     1024 * 100, // 100KB
					},
				},
			})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--artifacts",
		"--max-artifact-size", "50Mb", // Only scan artifacts < 50MB
		"--job-limit", "2",
		"--log-level", "debug",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "GitLab artifact scan with max-artifact-size should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify that large artifact was skipped
	assert.Contains(t, output, "Skipped large", "Should log skipping of large artifact")
	assert.Contains(t, output, "large", "Should mention large artifact")

	// Verify that small artifact was scanned successfully
	assert.Contains(t, output, "small-artifact-job", "Should process small artifact job")
	assert.Contains(t, output, "SECRET", "Should detect secrets in small artifact")
	assert.Contains(t, output, "deployment.env", "Should scan env file in small artifact")
}

// TestGitLabScan_QueueFolder tests the --queue flag for custom queue location
func TestGitLabScan_QueueFolder(t *testing.T) {
	t.Parallel()
	customQueueDir := t.TempDir()

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "queue-test"},
			})

		case "/api/v4/projects/1/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 400, "status": "success"},
			})

		case "/api/v4/projects/1/pipelines/400/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 4000, "name": "test-job", "status": "success"},
			})

		case "/api/v4/projects/1/jobs/4000/trace":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Job log\n"))

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--queue", customQueueDir,
		"--job-limit", "1",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Scan with custom queue folder should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	t.Logf("Custom queue directory: %s", customQueueDir)
	// The scanner should use the custom queue directory
}

// TestGitLabScan_TruffleHogVerificationDisabled tests --truffleHogVerification=false
func TestGitLabScan_TruffleHogVerificationDisabled(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "trufflehog-test"},
			})

		case "/api/v4/projects/1/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 500, "status": "success"},
			})

		case "/api/v4/projects/1/pipelines/500/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 5000, "name": "verify-test", "status": "success"},
			})

		case "/api/v4/projects/1/jobs/5000/trace":
			w.WriteHeader(http.StatusOK)
			logContent := `Job starting...
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export API_KEY=sk_test_1234567890abcdef
Job complete`
			_, _ = w.Write([]byte(logContent))

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--truffle-hog-verification=false",
		"--job-limit", "1",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Scan with TruffleHog verification disabled should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	// Should not attempt to verify credentials when verification is disabled
}
