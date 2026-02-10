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

// TestAzureDevOpsScan_ConfidenceFilter tests the --confidence flag
func TestAzureDevOpsScan_ConfidenceFilter(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("Azure DevOps Mock (Confidence): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/myorg/_apis/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "proj-1", "name": "confidence-test"},
				},
			})

		case "/myorg/confidence-test/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id": 200, "buildNumber": "1",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{
								"href": "https://dev.azure.com/myorg/confidence-test/_build/results?buildId=200",
							},
						},
					},
				},
			})

		case "/myorg/confidence-test/_apis/build/builds/200/logs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": 1, "url": "https://dev.azure.com/myorg/confidence-test/_apis/build/builds/200/logs/1"},
				},
			})

		case "/myorg/confidence-test/_apis/build/builds/200/logs/1":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			logContent := `Starting build...
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export POSSIBLE_SECRET=maybe_secret_123
Build complete`
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
		"--confidence", "high,medium",
	}, nil, 30*time.Second)

	assert.Nil(t, exitErr, "Scan with confidence filter should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	// Should only report high and medium confidence secrets
}

// TestAzureDevOpsScan_MaxArtifactSize tests the --max-artifact-size flag for Azure DevOps
func TestAzureDevOpsScan_MaxArtifactSize(t *testing.T) {

	// Create small artifact with secrets
	var smallArtifactBuf bytes.Buffer
	smallZipWriter := zip.NewWriter(&smallArtifactBuf)
	smallFile, _ := smallZipWriter.Create("secrets.txt")
	_, _ = smallFile.Write([]byte(`ADMIN_PASSWORD=VerySecretPass123!
STRIPE_API_KEY=test_api_abcdefghijklmnopqrstuvwxyz1234567890
DATABASE_URL=postgresql://admin:SuperSecretP@ss@db.local:5432/prod
`))
	_ = smallZipWriter.Close()

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("Azure DevOps Mock (MaxArtifactSize): %s %s", r.Method, r.URL.Path)

		serverURL := "http://" + r.Host

		switch r.URL.Path {
		case "/_apis/profile/profiles/me":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":          "user-123",
				"displayName": "Test User",
			})

		case "/_apis/accounts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"accountId":   "org-123",
						"accountName": "TestOrg",
					},
				},
			})

		case "/TestOrg/_apis/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":   "proj-123",
						"name": "TestProject",
					},
				},
			})

		case "/TestOrg/TestProject/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":     1000,
						"status": "completed",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{
								"href": serverURL + "/build/1000",
							},
						},
					},
				},
			})

		case "/TestOrg/TestProject/_apis/build/builds/1000/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":   2001,
						"name": "large-artifact",
						"resource": map[string]interface{}{
							"type": "Container",
							"properties": map[string]interface{}{
								"artifactsize": "104857600", // 100MB
							},
							"downloadUrl": serverURL + "/download/large",
						},
					},
					{
						"id":   2002,
						"name": "small-artifact",
						"resource": map[string]interface{}{
							"type": "Container",
							"properties": map[string]interface{}{
								"artifactsize": "102400", // 100KB
							},
							"downloadUrl": serverURL + "/download/small",
						},
					},
				},
			})

		case "/download/large":
			t.Error("Large artifact should not be downloaded")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PK\x03\x04"))

		case "/download/small":
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
		"ad", "scan",
		"--devops", server.URL,
		"--token", "test-token",
		"--username", "testuser",
		"--organization", "TestOrg",
		"--project", "TestProject",
		"--artifacts",
		"--max-artifact-size", "50Mb",
		"--log-level", "debug",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Azure DevOps artifact scan with max-artifact-size should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify that large artifact was skipped
	assert.Contains(t, output, "Skipped large artifact", "Should log skipping of large artifact")
	assert.Contains(t, output, "large-artifact", "Should mention large artifact name")

	// Verify that small artifact was scanned successfully
	assert.Contains(t, output, "small-artifact", "Should process small artifact")
	assert.Contains(t, output, "SECRET", "Should detect secrets in small artifact")
	assert.Contains(t, output, "secrets.txt", "Should scan secrets.txt file in small artifact")
}

// TestAzureDevOpsScan_ThreadsConfiguration tests the --threads flag
func TestAzureDevOpsScan_ThreadsConfiguration(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/testorg/_apis/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "proj-1", "name": "thread-test-1"},
					{"id": "proj-2", "name": "thread-test-2"},
					{"id": "proj-3", "name": "thread-test-3"},
				},
			})

		case "/testorg/thread-test-1/_apis/build/builds",
			"/testorg/thread-test-2/_apis/build/builds",
			"/testorg/thread-test-3/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id": 100, "buildNumber": "1",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{"href": "https://dev.azure.com/testorg/_build/results?buildId=100"},
						},
					},
				},
			})

		case "/testorg/thread-test-1/_apis/build/builds/100/logs",
			"/testorg/thread-test-2/_apis/build/builds/100/logs",
			"/testorg/thread-test-3/_apis/build/builds/100/logs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": 1, "url": "https://dev.azure.com/_apis/build/builds/100/logs/1"},
				},
			})

		case "/testorg/thread-test-1/_apis/build/builds/100/logs/1",
			"/testorg/thread-test-2/_apis/build/builds/100/logs/1",
			"/testorg/thread-test-3/_apis/build/builds/100/logs/1":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Build log\n"))

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
		}
	})
	defer cleanup()

	// Test with different thread counts
	for _, threads := range []string{"2", "8", "16"} {
		t.Run("threads_"+threads, func(t *testing.T) {
			stdout, stderr, exitErr := testutil.RunCLI(t, []string{
				"ad", "scan",
				"--devops", server.URL,
				"--token", "azure-pat-token",
				"--username", "testuser",
				"--organization", "testorg",
				"--threads", threads,
			}, nil, 15*time.Second)

			assert.Nil(t, exitErr, "Scan with %s threads should succeed", threads)

			output := stdout + stderr
			t.Logf("Output (threads=%s):\n%s", threads, output)
		})
	}
}

// TestAzureDevOpsScan_MaxBuilds tests the --max-builds flag
func TestAzureDevOpsScan_MaxBuilds(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/myorg/_apis/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "proj-1", "name": "maxbuilds-test"},
				},
			})

		case "/myorg/maxbuilds-test/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			// Return multiple builds
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id": 1, "buildNumber": "1",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{"href": "https://dev.azure.com/myorg/_build/results?buildId=1"},
						},
					},
					{
						"id": 2, "buildNumber": "2",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{"href": "https://dev.azure.com/myorg/_build/results?buildId=2"},
						},
					},
					{
						"id": 3, "buildNumber": "3",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{"href": "https://dev.azure.com/myorg/_build/results?buildId=3"},
						},
					},
					{
						"id": 4, "buildNumber": "4",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{"href": "https://dev.azure.com/myorg/_build/results?buildId=4"},
						},
					},
					{
						"id": 5, "buildNumber": "5",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{"href": "https://dev.azure.com/myorg/_build/results?buildId=5"},
						},
					},
				},
			})

		case "/myorg/maxbuilds-test/_apis/build/builds/1/logs",
			"/myorg/maxbuilds-test/_apis/build/builds/2/logs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": 1, "url": "https://dev.azure.com/_apis/build/builds/logs/1"},
				},
			})

		case "/myorg/maxbuilds-test/_apis/build/builds/1/logs/1",
			"/myorg/maxbuilds-test/_apis/build/builds/2/logs/1":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Build log\n"))

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
		"--max-builds", "2", // Limit to 2 builds
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Scan with max-builds limit should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	// Should only scan up to 2 builds per project
}

// TestAzureDevOpsScan_VerboseLogging tests the --verbose flag
func TestAzureDevOpsScan_VerboseLogging(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/myorg/_apis/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "proj-1", "name": "verbose-test"},
				},
			})

		case "/myorg/verbose-test/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id": 300, "buildNumber": "1",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{"href": "https://dev.azure.com/myorg/_build/results?buildId=300"},
						},
					},
				},
			})

		case "/myorg/verbose-test/_apis/build/builds/300/logs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": 1, "url": "https://dev.azure.com/_apis/build/builds/300/logs/1"},
				},
			})

		case "/myorg/verbose-test/_apis/build/builds/300/logs/1":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Build executing\n"))

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
		"--verbose",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Scan with verbose logging should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	// Verbose mode should produce detailed debug logs
	// The actual log level check would require inspecting the output format
}

// TestAzureDevOpsScan_TruffleHogVerificationDisabled tests --truffle-hog-verification=false
func TestAzureDevOpsScan_TruffleHogVerificationDisabled(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/myorg/_apis/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "proj-1", "name": "trufflehog-test"},
				},
			})

		case "/myorg/trufflehog-test/_apis/build/builds":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id": 400, "buildNumber": "1",
						"_links": map[string]interface{}{
							"web": map[string]interface{}{"href": "https://dev.azure.com/myorg/_build/results?buildId=400"},
						},
					},
				},
			})

		case "/myorg/trufflehog-test/_apis/build/builds/400/logs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": 1, "url": "https://dev.azure.com/_apis/build/builds/400/logs/1"},
				},
			})

		case "/myorg/trufflehog-test/_apis/build/builds/400/logs/1":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			logContent := `Starting build...
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Build complete`
			_, _ = w.Write([]byte(logContent))

		case "/myorg/trufflehog-test/_apis/build/builds/400/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":   1,
						"name": "drop",
						"resource": map[string]interface{}{
							"downloadUrl": "http://" + r.Host + "/myorg/trufflehog-test/_apis/build/builds/400/artifacts/drop",
						},
					},
				},
			})

		case "/myorg/trufflehog-test/_apis/build/builds/400/artifacts/drop":
			// Return small zip artifact
			var zipBuf bytes.Buffer
			zipWriter := zip.NewWriter(&zipBuf)
			file, _ := zipWriter.Create("artifact.txt")
			_, _ = file.Write([]byte("API_KEY=sk_test_123456789\n"))
			_ = zipWriter.Close()

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
		"--truffle-hog-verification=false",
		"--artifacts",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Scan with TruffleHog verification disabled should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
	// Should not attempt to verify credentials when verification is disabled
}
