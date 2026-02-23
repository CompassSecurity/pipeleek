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

func TestGiteaScan_HappyPath(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			// Gitea version/API check
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"version": "1.20.0",
			})

		case "/api/v1/user/repos":
			// Return list of repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        1,
					"name":      "test-repo",
					"full_name": "user/test-repo",
					"owner": map[string]interface{}{
						"login": "user",
					},
				},
			})

		case "/api/v1/repos/user/test-repo/actions/runs":
			// Return workflow runs
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"total_count": 1,
				"workflow_runs": []map[string]interface{}{
					{
						"id":         100,
						"status":     "completed",
						"conclusion": "success",
					},
				},
			})

		case "/api/v1/repos/user/test-repo/actions/runs/100/jobs":
			// Return jobs for workflow run
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"total_count": 1,
				"jobs": []map[string]interface{}{
					{
						"id":     1000,
						"name":   "test-job",
						"status": "completed",
					},
				},
			})

		case "/api/v1/repos/user/test-repo/actions/runs/100/jobs/1000/logs":
			// Return job logs
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Job execution log\nNo secrets here\n"))

		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token-123",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Gitea scan should succeed")

	// Verify API calls
	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make at least one API request")

	// Verify authentication header (Gitea uses token in query or header)
	hasAuthRequest := false
	for _, req := range requests {
		if req.Headers.Get("Authorization") != "" || req.RawQuery != "" {
			hasAuthRequest = true
			break
		}
	}
	assert.True(t, hasAuthRequest, "Should include authentication")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaScan_MaxArtifactSize tests the --max-artifact-size flag for Gitea
func TestGiteaScan_Artifacts_MaxArtifactSize(t *testing.T) {
	t.Parallel()
	// Create small artifact with secrets
	var smallArtifactBuf bytes.Buffer
	smallZipWriter := zip.NewWriter(&smallArtifactBuf)
	smallFile, _ := smallZipWriter.Create("app-config.yaml")
	_, _ = smallFile.Write([]byte(`database:
  password: SuperSecretDBPass123!
  connection_string: mongodb://admin:SecretMongoP@ss@cluster.example.com/prod
api:
  key: test_prod_key_abcdefghijklmnopqrstuvwxyz1234567890ABCDEF
`))
	_ = smallZipWriter.Close()

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("Gitea Mock (MaxArtifactSize): %s %s", r.Method, r.URL.Path)

		serverURL := "http://" + r.Host

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			// Gitea version check
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"version": "1.20.0",
			})

		case "/api/v1/repos/search":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id":        1,
						"name":      "test-repo",
						"full_name": "user/test-repo",
						"html_url":  serverURL + "/user/test-repo",
						"owner": map[string]interface{}{
							"login": "user",
						},
					},
				},
			})

		case "/api/v1/repos/user/test-repo/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{
						"id":     100,
						"name":   "test-workflow",
						"status": "completed",
					},
				},
				"total_count": 1,
			})

		case "/api/v1/repos/user/test-repo/actions/runs/100/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"artifacts": []map[string]interface{}{
					{
						"id":                   1001,
						"name":                 "large-artifact",
						"size_in_bytes":        100 * 1024 * 1024, // 100MB
						"archive_download_url": serverURL + "/api/v1/repos/user/test-repo/actions/artifacts/1001/zip",
					},
					{
						"id":                   1002,
						"name":                 "small-artifact",
						"size_in_bytes":        100 * 1024, // 100KB
						"archive_download_url": serverURL + "/api/v1/repos/user/test-repo/actions/artifacts/1002/zip",
					},
				},
				"total_count": 2,
			})

		case "/api/v1/repos/user/test-repo/actions/artifacts/1001/zip":
			t.Error("Large artifact should not be downloaded")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PK\x03\x04"))

		case "/api/v1/repos/user/test-repo/actions/artifacts/1002/zip":
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
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "test-token",
		"--artifacts",
		"--max-artifact-size", "50Mb",
		"--log-level", "debug",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Gitea artifact scan with max-artifact-size should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify that large artifact was skipped
	assert.Contains(t, output, "Skipped large artifact", "Should log skipping of large artifact")
	assert.Contains(t, output, "large-artifact", "Should mention large artifact name")

	// Verify that small artifact was scanned successfully
	assert.Contains(t, output, "small-artifact", "Should process small artifact")
	assert.Contains(t, output, "SECRET", "Should detect secrets in small artifact")
	assert.Contains(t, output, "app-config.yaml", "Should scan config file in small artifact")
}

// TestGiteaScan_WithArtifacts tests scanning with artifacts enabled

func TestGiteaScan_Owned(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		case "/api/v1/user/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "my-repo", "owner": map[string]string{"login": "me"}},
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"--owned",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with --owned flag")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaScan_Organization tests scanning organization repositories

func TestGiteaScan_Organization(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		case "/api/v1/orgs/my-org/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "org-repo", "full_name": "my-org/org-repo"},
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"--organization", "my-org",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with --organization")

	requests := getRequests()
	orgRequestFound := false
	for _, req := range requests {
		if req.Path == "/api/v1/orgs/my-org/repos" {
			orgRequestFound = true
			break
		}
	}

	t.Logf("Organization request found: %v", orgRequestFound)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaScan_SpecificRepository tests scanning a single repository

func TestGiteaScan_SpecificRepository(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		case "/api/v1/repos/owner/repo-name":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":        1,
				"name":      "repo-name",
				"full_name": "owner/repo-name",
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"--repository", "owner/repo-name",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with --repository")

	requests := getRequests()
	specificRepoFound := false
	for _, req := range requests {
		if req.Path == "/api/v1/repos/owner/repo-name" {
			specificRepoFound = true
			break
		}
	}

	t.Logf("Specific repository request found: %v", specificRepoFound)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaScan_WithCookie tests cookie authentication

func TestGiteaScan_WithCookie(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check for cookie header
		cookie := r.Header.Get("Cookie")
		if cookie != "" && cookie == "i_like_gitea=test-cookie-value" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-repo"},
			})
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "unauthorized"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"--cookie", "test-cookie-value",
	}, nil, 10*time.Second)

	// Cookie handling depends on implementation
	requests := getRequests()
	hasCookie := false
	for _, req := range requests {
		if req.Headers.Get("Cookie") != "" {
			hasCookie = true
			break
		}
	}

	t.Logf("Cookie sent: %v", hasCookie)
	t.Logf("Exit error: %v", exitErr)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaScan_RunsLimit tests limiting workflow runs scanned

func TestGiteaScan_RunsLimit(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		case "/api/v1/user/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-repo", "full_name": "user/test-repo"},
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"--runs-limit", "5",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with --runs-limit")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaScan_StartRunID tests starting from specific run ID

func TestGiteaScan_StartRunID(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{})
	})
	defer cleanup()

	// start-run-id requires --repository flag
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"--repository", "owner/repo",
		"--start-run-id", "100",
	}, nil, 10*time.Second)

	t.Logf("Exit error: %v", exitErr)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaScan_StartRunID_WithoutRepo tests validation error

func TestGiteaScan_StartRunID_WithoutRepo(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, testutil.MockSuccessResponse())
	defer cleanup()

	// Should fail: start-run-id without --repository
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"--start-run-id", "100",
	}, nil, 5*time.Second)

	// Should error about missing --repository
	assert.NotNil(t, exitErr, "Should fail when --start-run-id used without --repository")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

// TestGiteaScan_InvalidURL tests invalid Gitea URL handling

func TestGiteaScan_Threads(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"--threads", "8",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with --threads")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaScan_Verbose tests verbose logging

func TestGiteaScan_Verbose(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"-v",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with -v flag")

	// Verbose output may contain more details
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaEnum tests Gitea enumeration command

func TestGiteaScan_TruffleHogVerification(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "verification_enabled_default",
			args: []string{"gitea", "scan", "--gitea", server.URL, "--token", "test"},
		},
		{
			name: "verification_disabled",
			args: []string{"gitea", "scan", "--gitea", server.URL, "--token", "test", "--truffle-hog-verification=false"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, exitErr := testutil.RunCLI(t, tt.args, nil, 10*time.Second)

			assert.Nil(t, exitErr, "Command should succeed")

			t.Logf("STDOUT:\n%s", stdout)
			t.Logf("STDERR:\n%s", stderr)
		})
	}
}

// TestGiteaScan_ConfidenceFilter tests confidence level filtering

func TestGiteaScan_ConfidenceFilter(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "test",
		"--confidence", "high,medium",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with --confidence filter")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

func TestGiteaScan_WithArtifacts(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1", "/api/v1/version":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "1.20.0"})
		case "/api/v1/user/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-repo", "full_name": "user/test-repo"},
			})

		case "/api/v1/repos/user/test-repo/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{"id": 100, "status": "completed"},
				},
			})

		case "/api/v1/repos/user/test-repo/actions/runs/100/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jobs": []map[string]interface{}{
					{"id": 1000, "name": "build"},
				},
			})

		case "/api/v1/repos/user/test-repo/actions/runs/100/artifacts":
			// Return artifacts list
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"artifacts": []map[string]interface{}{
					{"id": 1, "name": "build-artifacts"},
				},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gitea", "scan",
		"--gitea", server.URL,
		"--token", "gitea-token",
		"--artifacts",
		"--runs-limit", "1",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Command should succeed with --artifacts")

	requests := getRequests()
	t.Logf("Made %d requests", len(requests))
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGiteaScan_Owned tests scanning only owned repositories
