package e2e

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabScan_JobStatus(t *testing.T) {
	tests := []struct {
		name       string
		flags      []string
		env        []string
		wantScope  []string
		wantJobs   []string
		wantSource string
	}{
		{name: "default scans all", wantJobs: []string{"1", "2", "3"}},
		{name: "comma separated", flags: []string{"--job-status", "success,failed"}, wantScope: []string{"success", "failed"}, wantJobs: []string{"1", "2"}},
		{name: "repeated", flags: []string{"--job-status", "success", "--job-status", "failed"}, wantScope: []string{"success", "failed"}, wantJobs: []string{"1", "2"}},
		{name: "environment", env: []string{"PIPELEEK_GITLAB_SCAN_JOB_STATUS=failed"}, wantScope: []string{"failed"}, wantJobs: []string{"2"}},
		{name: "CLI overrides environment", flags: []string{"--job-status", "success"}, env: []string{"PIPELEEK_GITLAB_SCAN_JOB_STATUS=failed"}, wantScope: []string{"success"}, wantJobs: []string{"1"}},
		{name: "job limit counts matches", flags: []string{"--job-status", "failed", "--job-limit", "1"}, wantScope: []string{"failed"}, wantJobs: []string{"2"}},
		{name: "numeric hit timeout", env: []string{"PIPELEEK_COMMON_HIT_TIMEOUT=120"}, wantJobs: []string{"1", "2", "3"}},
		{name: "duration hit timeout", flags: []string{"--hit-timeout", "2m"}, wantJobs: []string{"1", "2", "3"}},
		{name: "pipeline source", flags: []string{"--pipeline-source", "schedule"}, wantSource: "schedule", wantJobs: []string{"2"}},
		{name: "pipeline source and status", flags: []string{"--pipeline-source", "push", "--job-status", "success"}, wantSource: "push", wantScope: []string{"success"}, wantJobs: []string{"1"}},
		{name: "no matching jobs", flags: []string{"--pipeline-source", "schedule", "--job-status", "success"}, wantSource: "schedule", wantScope: []string{"success"}},
		{name: "pipeline source environment", env: []string{"PIPELEEK_GITLAB_SCAN_PIPELINE_SOURCE=schedule"}, wantSource: "schedule", wantJobs: []string{"2"}},
		{name: "pipeline source CLI precedence", flags: []string{"--pipeline-source", "push", "--job-limit", "1"}, env: []string{"PIPELEEK_GITLAB_SCAN_PIPELINE_SOURCE=schedule"}, wantSource: "push", wantJobs: []string{"1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PIPELEEK_GITLAB_SCAN_JOB_STATUS", "")
			t.Setenv("PIPELEEK_GITLAB_SCAN_PIPELINE_SOURCE", "")
			var artifact bytes.Buffer
			require.NoError(t, zip.NewWriter(&artifact).Close())
			server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/api/v4/version":
					_, _ = w.Write([]byte(`{"version":"18.0.0"}`))
				case r.URL.Path == "/api/v4/projects":
					_, _ = w.Write([]byte(`[{"id":1,"path_with_namespace":"group/project"}]`))
				case r.URL.Path == "/api/v4/projects/1/pipelines":
					pipelines := []map[string]interface{}{
						{"id": 10, "source": "push"},
						{"id": 20, "source": "schedule"},
					}
					var selected []map[string]interface{}
					for _, pipeline := range pipelines {
						if r.URL.Query().Get("source") == pipeline["source"] {
							selected = append(selected, pipeline)
						}
					}
					assert.NoError(t, json.NewEncoder(w).Encode(selected))
				case r.URL.Path == "/api/v4/projects/1/jobs" ||
					r.URL.Path == "/api/v4/projects/1/pipelines/10/jobs" ||
					r.URL.Path == "/api/v4/projects/1/pipelines/20/jobs":
					scope := r.URL.Query()["scope[]"]
					var jobs []map[string]interface{}
					for i, status := range []string{"success", "failed", "running"} {
						if r.URL.Path == "/api/v4/projects/1/pipelines/10/jobs" && status == "failed" ||
							r.URL.Path == "/api/v4/projects/1/pipelines/20/jobs" && status != "failed" {
							continue
						}
						if len(scope) > 0 && !slices.Contains(scope, status) {
							continue
						}
						jobs = append(jobs, map[string]interface{}{
							"id": i + 1, "name": status, "status": status,
							"artifacts_file": map[string]interface{}{"filename": "artifacts.zip", "size": artifact.Len()},
						})
					}
					assert.NoError(t, json.NewEncoder(w).Encode(jobs))
				case strings.HasSuffix(r.URL.Path, "/trace"):
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte("Build complete, no secrets\n"))
				case strings.HasSuffix(r.URL.Path, "/artifacts"):
					w.Header().Set("Content-Type", "application/zip")
					_, _ = w.Write(artifact.Bytes())
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			})
			defer cleanup()

			args := append([]string{"gl", "scan", "--url", server.URL, "--token", "glpat-test-token", "--artifacts"}, tt.flags...)
			stdout, stderr, err := testutil.RunCLI(t, args, tt.env, 30*time.Second)
			require.NoError(t, err, "%s\n%s", stdout, stderr)
			var traces, artifacts []string
			jobRequests := 0
			pipelineRequests := 0
			for _, req := range getRequests() {
				if req.Path == "/api/v4/projects/1/pipelines" {
					pipelineRequests++
					query, err := url.ParseQuery(req.RawQuery)
					require.NoError(t, err)
					assert.Equal(t, tt.wantSource, query.Get("source"))
				}
				if req.Path == "/api/v4/projects/1/jobs" ||
					req.Path == "/api/v4/projects/1/pipelines/10/jobs" ||
					req.Path == "/api/v4/projects/1/pipelines/20/jobs" {
					jobRequests++
					if tt.wantSource != "" {
						assert.NotEqual(t, "/api/v4/projects/1/jobs", req.Path)
					}
					query, err := url.ParseQuery(req.RawQuery)
					require.NoError(t, err)
					assert.Equal(t, tt.wantScope, query["scope[]"])
					if tt.wantSource != "" {
						assert.Equal(t, "true", query.Get("include_retried"))
					}
				}
				for _, id := range []int{1, 2, 3} {
					jobID := strconv.Itoa(id)
					if req.Path == "/api/v4/projects/1/jobs/"+jobID+"/trace" {
						traces = append(traces, jobID)
					}
					if req.Path == "/api/v4/projects/1/jobs/"+jobID+"/artifacts" {
						artifacts = append(artifacts, jobID)
					}
				}
			}
			assert.Equal(t, 1, jobRequests)
			if tt.wantSource == "" {
				assert.Zero(t, pipelineRequests)
			} else {
				assert.Equal(t, 1, pipelineRequests)
			}
			assert.ElementsMatch(t, tt.wantJobs, traces)
			assert.ElementsMatch(t, tt.wantJobs, artifacts)
		})
	}
}

func TestGitLabScan_InvalidJobStatus(t *testing.T) {
	for _, env := range []bool{false, true} {
		name := "flag"
		if env {
			name = "environment"
		}

		t.Run(name, func(t *testing.T) {
			server, requests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("invalid status must be rejected before API requests: %s", r.URL)
				w.WriteHeader(http.StatusNotFound)
			})
			defer cleanup()
			args := []string{"gl", "scan", "--url", server.URL, "--token", "glpat-test-token"}
			var overrides []string
			if env {
				overrides = []string{"PIPELEEK_GITLAB_SCAN_JOB_STATUS=invalid"}
			} else {
				args = append(args, "--job-status", "invalid")
			}
			stdout, stderr, err := testutil.RunCLI(t, args, overrides, 15*time.Second)
			require.Error(t, err)
			assert.Contains(t, stdout+stderr, `invalid job status`)
			assert.Empty(t, requests())
		})
	}
}

func TestGitLabScan_InvalidPipelineSource(t *testing.T) {
	for _, useEnv := range []bool{false, true} {
		name := "flag"
		if useEnv {
			name = "environment"
		}
		t.Run(name, func(t *testing.T) {
			server, requests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("invalid source must be rejected before API requests: %s", r.URL)
				w.WriteHeader(http.StatusNotFound)
			})
			defer cleanup()
			args := []string{"gl", "scan", "--url", server.URL, "--token", "glpat-test-token"}
			var env []string
			if useEnv {
				env = []string{"PIPELEEK_GITLAB_SCAN_PIPELINE_SOURCE=invalid"}
			} else {
				args = append(args, "--pipeline-source", "invalid")
			}
			stdout, stderr, err := testutil.RunCLI(t, args, env, 15*time.Second)
			require.Error(t, err)
			assert.Contains(t, stdout+stderr, "invalid pipeline source")
			assert.Empty(t, requests())
		})
	}
}

// TestGitLabScan_ConfidenceFilter tests the --confidence flag
func TestGitLabScan_ConfidenceFilter(t *testing.T) {

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
		"--url", server.URL,
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
		"--url", server.URL,
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
		"--url", server.URL,
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
		"--url", server.URL,
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

// TestGitLabScan_SecretsVerificationDisabled tests --secretsVerification=false
func TestGitLabScan_SecretsVerificationDisabled(t *testing.T) {

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
		"--url", server.URL,
		"--token", "glpat-test-token",
		"--secrets-verification=false",
		"--job-limit", "1",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Scan with TruffleHog verification disabled should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	// Should not attempt to verify credentials when verification is disabled
}
