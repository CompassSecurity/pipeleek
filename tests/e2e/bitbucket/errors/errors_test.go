package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestBitBucketScan_MissingCredentials(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		// Return 401 Unauthorized for all requests when credentials are missing/invalid
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"message": "Invalid credentials",
			},
		})
	})
	defer cleanup()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--owned",              // Need a scan mode
		"-a",                   // Artifacts flag
		"-c", "invalid-cookie", // Cookie flag
		"-t", "invalid-token", // Token flag
		"-e", "test@example.com", // Email flag
	}, nil, 30*time.Second)

	// The command exits early with authentication error when trying to get user info
	output := stdout + stderr
	assert.Contains(t, output, "401", "Should show 401 authentication error when credentials missing")
	assert.Contains(t, output, "Failed to get user info", "Should fail at user info validation")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Owned_Unauthorized(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"message": "Unauthorized",
			},
		})
	})
	defer cleanup()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "baduser",
		"--token", "badtoken",
		"--owned",
	}, nil, 30*time.Second)

	output := stdout + stderr
	assert.Contains(t, output, "401", "Should log 401 error")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Owned_NotFound(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"message": "Not Found",
			},
		})
	})
	defer cleanup()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testtoken",
		"--owned",
	}, nil, 30*time.Second)

	output := stdout + stderr
	assert.Contains(t, output, "404", "Should log 404 error")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Workspace_NotFound(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/repositories/invalid-workspace" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type": "error",
				"error": map[string]interface{}{
					"message": "Workspace not found",
				},
			})
		} else {
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
		"--workspace", "invalid-workspace",
	}, nil, 30*time.Second)

	output := stdout + stderr
	assert.Contains(t, output, "404", "Should log 404 error for invalid workspace")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_Public_ServerError(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"message": "Internal Server Error",
			},
		})
	})
	defer cleanup()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"bb", "scan",
		"--bitbucket", server.URL,
		"--email", "testuser",
		"--token", "testtoken",
		"--public",
	}, nil, 5*time.Second)

	output := stdout + stderr
	assert.Contains(t, output, "500", "Should log 500 error")
	t.Logf("Output:\n%s", output)
}

func TestBitBucketScan_InvalidCookie(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock: %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/!api/2.0/user":
			// Return 401 for invalid cookie
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type": "error",
				"error": map[string]interface{}{
					"message": "Unauthorized",
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
		"--cookie", "invalid-cookie",
		"--workspace", "test-workspace",
		"--artifacts",
	}, nil, 10*time.Second)

	// Should exit due to fatal error on invalid cookie
	assert.NotNil(t, exitErr, "Should fail with invalid cookie")

	output := stdout + stderr
	assert.Contains(t, output, "Failed to get user info", "Should log cookie validation failure")
	assert.Contains(t, output, "401", "Should show 401 status")

	t.Logf("Output:\n%s", output)
}
