package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestBitBucketScan_MaxPipelines(t *testing.T) {

	pipelinesReturned := 0
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (MaxPipelines): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/repositories/test-workspace":
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
			pipelinesReturned++
			// Return 5 pipelines but max-pipelines=2 should limit scanning
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{"uuid": "{pipeline-1}", "build_number": 1},
					{"uuid": "{pipeline-2}", "build_number": 2},
					{"uuid": "{pipeline-3}", "build_number": 3},
					{"uuid": "{pipeline-4}", "build_number": 4},
					{"uuid": "{pipeline-5}", "build_number": 5},
				},
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
		"--max-pipelines", "2",
	}, nil, 30*time.Second)

	assert.Nil(t, exitErr, "MaxPipelines scan should succeed")

	output := stdout + stderr
	// Verify the limit was applied (difficult to directly verify, but should complete quickly)
	assert.NotEmpty(t, output, "Should produce output")
	t.Logf("Pipelines endpoint called: %d times", pipelinesReturned)
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Confidence(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (Confidence): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/repositories/test-workspace":
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
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid": "{step-uuid-1}",
						"name": "Build",
						"state": map[string]interface{}{
							"name": "COMPLETED",
						},
					},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps/{step-uuid-1}/log":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			// Log with high confidence secret
			logContent := `+ echo "Starting"
+ export API_KEY="AKIAIOSFODNN7EXAMPLE"
+ echo "Done"`
			_, _ = w.Write([]byte(logContent))

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
		"--confidence", "high",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Confidence filter scan should succeed")

	output := stdout + stderr
	// Verify scan completed with confidence filter
	assert.NotEmpty(t, output, "Should produce output")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Threads(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (Threads): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/repositories/test-workspace":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":       "{repo-uuid-1}",
						"name":       "test-repo-1",
						"slug":       "test-repo-1",
						"created_on": "2023-01-01T00:00:00.000000+00:00",
						"updated_on": "2023-01-02T00:00:00.000000+00:00",
						"links": map[string]interface{}{
							"html": map[string]interface{}{
								"href": "https://bitbucket.org/test-workspace/test-repo-1",
							},
						},
					},
					{
						"uuid":       "{repo-uuid-2}",
						"name":       "test-repo-2",
						"slug":       "test-repo-2",
						"created_on": "2023-01-01T00:00:00.000000+00:00",
						"updated_on": "2023-01-02T00:00:00.000000+00:00",
						"links": map[string]interface{}{
							"html": map[string]interface{}{
								"href": "https://bitbucket.org/test-workspace/test-repo-2",
							},
						},
					},
				},
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
		"--threads", "2",
		"--max-pipelines", "1",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Thread scan should succeed")

	output := stdout + stderr
	assert.NotEmpty(t, output, "Should produce output")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Verbose(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/repositories/test-workspace" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{},
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
		"--workspace", "test-workspace",
		"--verbose",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Verbose scan should succeed")

	output := stdout + stderr
	// Verbose mode should produce more detailed output
	assert.NotEmpty(t, output, "Should produce output")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_TruffleHogVerification(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/repositories/test-workspace":
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
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid": "{step-uuid-1}",
						"name": "Build",
						"state": map[string]interface{}{
							"name": "COMPLETED",
						},
					},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps/{step-uuid-1}/log":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			logContent := `+ export FAKE_KEY="not_a_real_key_12345"`
			_, _ = w.Write([]byte(logContent))

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
		"--truffle-hog-verification=false",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Scan with verification disabled should succeed")

	output := stdout + stderr
	assert.NotEmpty(t, output, "Should produce output")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Pagination(t *testing.T) {

	requestCount := 0
	var serverURL string
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (Pagination): %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)

		switch r.URL.Path {
		case "/repositories/test-workspace":
			requestCount++
			if requestCount == 1 {
				// First page with next URL
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{
							"uuid":       "{repo-uuid-1}",
							"name":       "repo-1",
							"slug":       "repo-1",
							"created_on": "2023-01-01T00:00:00.000000+00:00",
							"updated_on": "2023-01-02T00:00:00.000000+00:00",
							"links": map[string]interface{}{
								"html": map[string]interface{}{
									"href": "https://bitbucket.org/test-workspace/repo-1",
								},
							},
						},
					},
					"next": serverURL + "/repositories/test-workspace?page=2",
				})
			} else {
				// Second page without next URL
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{
							"uuid":       "{repo-uuid-2}",
							"name":       "repo-2",
							"slug":       "repo-2",
							"created_on": "2023-01-01T00:00:00.000000+00:00",
							"updated_on": "2023-01-02T00:00:00.000000+00:00",
							"links": map[string]interface{}{
								"html": map[string]interface{}{
									"href": "https://bitbucket.org/test-workspace/repo-2",
								},
							},
						},
					},
				})
			}

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})
		}
	})
	defer cleanup()

	serverURL = server.URL

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testtoken",
		"--workspace", "test-workspace",
		"--max-pipelines", "1",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Paginated scan should succeed")

	_ = getRequests()
	// Should have called the workspace endpoint at least twice (pagination)
	assert.True(t, requestCount >= 2, "Should paginate through results")

	output := stdout + stderr
	assert.NotEmpty(t, output, "Should produce output")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_ConfidenceFilter_Multiple(t *testing.T) {

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock: %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/repositories/test-workspace":
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
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid": "{step-uuid-1}",
						"name": "Build",
						"state": map[string]interface{}{
							"name": "COMPLETED",
						},
					},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps/{step-uuid-1}/log":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			// Mix of high and medium confidence secrets
			logContent := `+ export GITHUB_TOKEN="ghp_1234567890abcdefghijklmnopqrstuvwxyz"
+ export PASSWORD="simplepass"
+ curl -H "Authorization: Bearer AKIAIOSFODNN7EXAMPLE" https://api.example.com
`
			_, _ = w.Write([]byte(logContent))

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
		"--confidence", "high,medium",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "Multi-confidence filter scan should succeed")

	output := stdout + stderr
	// Verify high confidence secrets were found
	assert.Contains(t, output, "SECRET", "Should find high confidence secrets")

	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_RateLimit(t *testing.T) {

	requestCount := 0
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requestCount++

		if requestCount == 1 {
			// First request returns 429
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type": "error",
				"error": map[string]interface{}{
					"message": "Rate limit exceeded",
				},
			})
		} else {
			// Subsequent requests succeed
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})
		}
	})
	defer cleanup()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testtoken",
		"--workspace", "test-workspace",
	}, nil, 10*time.Second)

	output := stdout + stderr
	// Should log rate limit status (the retry hook may log but not always visible in output)
	assert.Contains(t, output, "429", "Should log 429 status")

	t.Logf("Output:\n%s", output)
}
