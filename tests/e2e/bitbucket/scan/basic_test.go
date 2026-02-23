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

func TestBitBucketScan_HappyPath(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		t.Logf("BitBucket Mock: %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/!api/2.0/user":
			// User info endpoint for cookie validation (internal API path)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"username":     "testuser",
				"display_name": "Test User",
				"uuid":         "{user-uuid-1}",
			})

		case "/repositories/test-workspace":
			// Return list of repositories in workspace
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":       "{repo-uuid-1}",
						"name":       "test-repo",
						"slug":       "test-repo",
						"created_on": "2023-01-01T00:00:00.000000+00:00",
						"updated_on": "2023-01-02T00:00:00.000000+00:00",
						"links": map[string]interface{}{
							"html": map[string]interface{}{
								"href": "https://bitbucket.org/test-workspace/test-repo",
							},
						},
					},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines":
			// Return list of pipelines
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":         "{pipeline-uuid-1}",
						"build_number": 1,
						"state": map[string]interface{}{
							"name": "COMPLETED",
						},
					},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps":
			// Return pipeline steps
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid": "{step-uuid-1}",
						"name": "Build and Test",
						"state": map[string]interface{}{
							"name": "COMPLETED",
						},
					},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps/{step-uuid-1}/log":
			// Return step logs containing credentials
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			logContent := `+ echo "Starting build process"
Starting build process
+ export DATABASE_URL="postgres://admin:SuperSecret123!@db.example.com:5432/mydb"
+ export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
+ echo "Running tests..."
Running tests...
+ curl -H "Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz" https://api.github.com/user
{"login": "testuser"}
+ echo "Build completed successfully"
Build completed successfully`
			_, _ = w.Write([]byte(logContent))

		case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/artifacts":
			// Return list of artifacts for pipeline
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":            "{artifact-uuid-1}",
						"step_uuid":       "{step-uuid-1}",
						"name":            "config.zip",
						"path":            "artifacts/config.zip",
						"artifactType":    "file",
						"file_size_bytes": 1024,
						"created_on":      "2023-01-01T00:00:00.000000+00:00",
						"storageType":     "s3",
						"key":             "artifacts/config.zip",
					},
				},
			})

		case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/artifacts/{artifact-uuid-1}/content":
			// Return an actual zip archive containing a file with credentials
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)

			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			f, _ := zw.Create("config.txt")
			// file content contains multiple secret-like strings to be detected
			_, _ = f.Write([]byte(`# Configuration file
API_KEY=sk-proj-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW
DATABASE_PASSWORD=MyArtifactSecret123!
STRIPE_SECRET_KEY=sk_live_51abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP`))
			_ = zw.Close()

			_, _ = w.Write(buf.Bytes())

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testpass",
		"--cookie", "test-cookie-value",
		"--workspace", "test-workspace",
		"--artifacts",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "BitBucket scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	// Verify Basic Auth
	hasAuthRequest := false
	for _, req := range requests {
		authHeader := req.Headers.Get("Authorization")
		if authHeader != "" {
			assert.Contains(t, authHeader, "Basic", "Should use Basic authentication")
			hasAuthRequest = true
		}
	}
	assert.True(t, hasAuthRequest, "Should have authenticated requests")

	// Verify credentials were detected in logs
	output := stdout + stderr

	// Check that the scanner detected the secrets in pipeline logs
	assert.Contains(t, output, "postgres://", "Should detect PostgreSQL connection string")
	assert.Contains(t, output, "AWS_SECRET_ACCESS_KEY", "Should detect AWS secret key")
	assert.Contains(t, output, "Github", "Should detect GitHub token")

	// Verify the scanner logged findings with HIT marker
	assert.Contains(t, output, "SECRET", "Should log SECRET for secret detection")
	assert.Contains(t, output, "ruleName", "Should log rule name for detected secrets")

	// Verify multiple secrets were found in logs
	assert.Contains(t, output, "Password in URL", "Should detect password in database URL")
	assert.Contains(t, output, "Github Personal Access Token", "Should detect GitHub PAT")

	// Verify artifact scanning produced findings
	assert.Contains(t, output, "SECRET", "Should log SECRET for artifact findings")

	// Check for secrets detected in artifacts (config file and known rule matches)
	assert.Contains(t, output, "config.txt", "Should include scanned artifact file name")
	assert.Contains(t, output, "Stripe Secret Key", "Should detect Stripe secret key in artifact")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

func TestBitBucketScan_Owned_HappyPath(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (Owned): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/user/permissions/workspaces":
			// Return owned workspaces
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"workspace": map[string]interface{}{
							"slug": "my-workspace",
							"name": "My Workspace",
							"uuid": "{workspace-uuid-1}",
						},
					},
				},
			})

		case "/repositories/my-workspace":
			// Return repositories in owned workspace
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":       "{repo-uuid-1}",
						"name":       "my-repo",
						"slug":       "my-repo",
						"created_on": "2023-01-01T00:00:00.000000+00:00",
						"updated_on": "2023-01-02T00:00:00.000000+00:00",
						"links": map[string]interface{}{
							"html": map[string]interface{}{
								"href": "https://bitbucket.org/my-workspace/my-repo",
							},
						},
					},
				},
			})

		case "/repositories/my-workspace/my-repo/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testtoken",
		"--owned",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Owned scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	output := stdout + stderr
	assert.Contains(t, output, "owned workspaces", "Should log owned workspace scanning")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Workspace_HappyPath(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (Workspace): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/repositories/test-workspace":
			// Return repositories in the workspace
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":       "{repo-uuid-1}",
						"name":       "workspace-repo",
						"slug":       "workspace-repo",
						"created_on": "2023-01-01T00:00:00.000000+00:00",
						"updated_on": "2023-01-02T00:00:00.000000+00:00",
						"links": map[string]interface{}{
							"html": map[string]interface{}{
								"href": "https://bitbucket.org/test-workspace/workspace-repo",
							},
						},
					},
				},
			})

		case "/repositories/test-workspace/workspace-repo/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testtoken",
		"--workspace", "test-workspace",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Workspace scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	output := stdout + stderr
	assert.Contains(t, output, "Scanning a workspace", "Should log workspace scanning")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Public_HappyPath(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (Public): %s %s", r.Method, r.URL.Path)

		if r.URL.Path == "/repositories" {
			// Return public repositories
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":       "{repo-uuid-1}",
						"name":       "public-repo",
						"slug":       "public-repo",
						"created_on": "2023-01-01T00:00:00.000000+00:00",
						"updated_on": "2023-01-02T00:00:00.000000+00:00",
						"is_private": false,
						"owner": map[string]interface{}{
							"username": "public-owner",
						},
						"links": map[string]interface{}{
							"html": map[string]interface{}{
								"href": "https://bitbucket.org/public-owner/public-repo",
							},
						},
					},
				},
			})
		} else {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testtoken",
		"--public",
		"--max-pipelines", "1",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Public scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	output := stdout + stderr
	assert.Contains(t, output, "public repos", "Should log public repo scanning")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Public_WithAfter(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (Public After): %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)

		if r.URL.Path == "/repositories" {
			// Check for after query parameter
			after := r.URL.Query().Get("after")
			t.Logf("After param: %s", after)

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":       "{repo-uuid-1}",
						"name":       "recent-public-repo",
						"slug":       "recent-public-repo",
						"created_on": "2025-04-03T00:00:00.000000+00:00",
						"updated_on": "2025-04-03T00:00:00.000000+00:00",
						"is_private": false,
						"owner": map[string]interface{}{
							"username": "recent-owner",
						},
						"links": map[string]interface{}{
							"html": map[string]interface{}{
								"href": "https://bitbucket.org/recent-owner/recent-public-repo",
							},
						},
					},
				},
			})
		} else {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testtoken",
		"--public",
		"--after", "2025-04-02T15:00:00+02:00",
		"--max-pipelines", "1",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Public scan with after filter should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	output := stdout + stderr
	assert.Contains(t, output, "public repos", "Should log public repo scanning")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_NoScanMode(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})
	})
	defer cleanup()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testtoken",
		// No --owned, --workspace, or --public flag
	}, nil, 5*time.Second)

	output := stdout + stderr
	assert.Contains(t, output, "Specify a scan mode", "Should show error for no scan mode")
	t.Logf("Output:\n%s", output)
}
