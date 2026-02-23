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

func TestAzureDevOpsScan_HappyPath(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch { //nolint:staticcheck
		case r.URL.Path == "/_apis/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "proj-1", "name": "test-project"},
				},
			})

		case r.URL.Path == "/proj-1/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": 1, "buildNumber": "1"},
				},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"ad", "scan",
		"--devops", server.URL,
		"--token", "azure-pat-token",
		"--username", "testuser",
		"--organization", "myorg",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Azure DevOps scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestAzureDevOpsScan_MissingToken tests missing required token

func TestAzureDevOpsScan_WithLogs(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("Azure DevOps Mock: %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/myorg/_apis/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "proj-1", "name": "test-project", "url": "https://dev.azure.com/myorg/_apis/projects/proj-1"},
				},
			})

		case "/myorg/test-project/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id": 123, "buildNumber": "20230101.1",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{
								"href": "https://dev.azure.com/myorg/test-project/_build/results?buildId=123",
							},
						},
					},
				},
			})

		case "/myorg/test-project/_apis/build/builds/123/logs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": 1, "url": "https://dev.azure.com/myorg/test-project/_apis/build/builds/123/logs/1"},
				},
			})

		case "/myorg/test-project/_apis/build/builds/123/logs/1":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			logContent := `2023-01-01T10:00:00.000Z Starting pipeline
2023-01-01T10:00:01.000Z Setting environment variables
2023-01-01T10:00:02.000Z export DATABASE_URL=postgresql://admin:superSecretP@ssw0rd123@db.example.com:5432/prod_db
2023-01-01T10:00:03.000Z export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
2023-01-01T10:00:04.000Z export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
2023-01-01T10:00:05.000Z Pipeline completed successfully`
			_, _ = w.Write([]byte(logContent))

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"ad", "scan",
		"--devops", server.URL,
		"--token", "azure-pat-token",
		"--username", "testuser",
		"--organization", "myorg",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Azure DevOps scan with logs should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 3, "Should make multiple API requests")

	output := stdout + stderr
	assert.Contains(t, output, "SECRET", "Should detect secrets in logs")
	assert.Contains(t, output, "Password in URL", "Should detect database password")
	t.Logf("Output:\n%s", output)
}

func TestAzureDevOpsScan_Artifacts_WithDotEnv(t *testing.T) {
	t.Parallel()
	// Create a zip with a .env file
	var zipBuf bytes.Buffer
	zipWriter := zip.NewWriter(&zipBuf)

	envFile, _ := zipWriter.Create(".env")
	envContent := `# Environment Configuration
DATABASE_URL=postgresql://admin:superSecretP@ssw0rd123@db.example.com:5432/prod_db
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51H8example123456789
GITHUB_TOKEN=ghp_examplePersonalAccessToken123456789
`
	_, _ = envFile.Write([]byte(envContent))
	_ = zipWriter.Close()

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("Azure DevOps Mock (Artifacts): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/myorg/_apis/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "proj-1", "name": "test-project"},
				},
			})

		case "/myorg/test-project/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":          456,
						"buildNumber": "20230102.1",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{
								"href": "https://dev.azure.com/myorg/test-project/_build/results?buildId=456",
							},
						},
					},
				},
			})

		case "/myorg/test-project/_apis/build/builds/456/logs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})

		case "/myorg/test-project/_apis/build/builds/456/artifacts":
			w.WriteHeader(http.StatusOK)
			downloadURL := "http://" + r.Host + "/download-artifact-456"
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":   "artifact-1",
						"name": "build-output",
						"resource": map[string]interface{}{
							"downloadUrl": downloadURL,
						},
					},
				},
			})

		case "/download-artifact-456":
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zipBuf.Bytes())

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"ad", "scan",
		"--devops", server.URL,
		"--token", "azure-pat-token",
		"--username", "testuser",
		"--organization", "myorg",
		"--artifacts",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "Artifact scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 3, "Should make API requests")

	output := stdout + stderr
	assert.Contains(t, output, "SECRET", "Should detect secrets in artifact")
	assert.Contains(t, output, ".env", "Should detect .env file")
	assert.Contains(t, output, "Password in URL", "Should detect database password")
	t.Logf("Output:\n%s", output)
}

// TestAzureDevOpsScan_Pagination tests pagination with continuation tokens

func TestAzureDevOpsScan_Pagination(t *testing.T) {
	t.Parallel()
	projectRequestCount := 0

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("Azure DevOps Mock (Pagination): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/myorg/_apis/projects":
			projectRequestCount++

			if projectRequestCount == 1 {
				// First page with continuation token
				w.Header().Set("x-ms-continuationtoken", "page2token")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"value": []map[string]interface{}{
						{"id": "proj-1", "name": "project-1"},
					},
				})
			} else {
				// Second page without continuation token
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"value": []map[string]interface{}{
						{"id": "proj-2", "name": "project-2"},
					},
				})
			}

		case "/myorg/project-1/_apis/build/builds", "/myorg/project-2/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"ad", "scan",
		"--devops", server.URL,
		"--token", "azure-pat-token",
		"--username", "testuser",
		"--organization", "myorg",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Pagination scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 2, "Should make multiple paginated requests")
	assert.GreaterOrEqual(t, projectRequestCount, 2, "Should paginate through projects")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	t.Logf("Project requests: %d", projectRequestCount)
}

// TestAzureDevOpsScan_Unauthorized tests 401 authentication failure

func TestAzureDevOpsScan_Project(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("Azure DevOps Mock (Project): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/myorg/MyProject/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": 100, "buildNumber": "100", "_links": map[string]interface{}{"web": map[string]interface{}{"href": "https://dev.azure.com/build/100"}}},
				},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"ad", "scan",
		"--devops", server.URL,
		"--token", "azure-pat-token",
		"--username", "testuser",
		"--organization", "myorg",
		"--project", "MyProject",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Project scan should succeed")

	requests := getRequests()
	// Should NOT call projects list endpoint, goes directly to builds
	hasProjectsList := false
	for _, req := range requests {
		if strings.Contains(req.Path, "/_apis/projects") {
			hasProjectsList = true
			break
		}
	}
	assert.False(t, hasProjectsList, "Should not list projects when specific project provided")

	output := stdout + stderr
	assert.Contains(t, output, "Scanning project", "Should log project scanning")
	t.Logf("Output:\n%s", output)
}
