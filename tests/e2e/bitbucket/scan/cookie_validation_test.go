package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

// TestBitBucketScan_CookieValidationOnlyWithArtifacts verifies that cookie validation
// (calling GetUserInfo via the /!api/2.0/user endpoint) only happens when BOTH
// --cookie (-c) AND --artifacts (-a) flags are provided together.
func TestBitBucketScan_CookieValidationOnlyWithArtifacts(t *testing.T) {
	t.Parallel()
	t.Run("WithoutCookie_WithoutArtifacts_NoValidation", func(t *testing.T) {
		userInfoCalled := false

		server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			t.Logf("BitBucket Mock: %s %s", r.Method, r.URL.Path)

			switch r.URL.Path {
			case "/!api/2.0/user":
				// This endpoint should NOT be called without cookie
				userInfoCalled = true
				t.Error("GetUserInfo should not be called without cookie")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"type": "error",
					"error": map[string]interface{}{
						"message": "Unauthorized",
					},
				})

			case "/2.0/user":
				// Regular user endpoint for token-based auth
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"uuid":         "user-123",
					"display_name": "Test User",
				})

			case "/2.0/workspaces":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{"slug": "test-workspace", "name": "Test Workspace"},
					},
				})

			case "/repositories/test-workspace":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{"slug": "test-repo", "name": "Test Repo"},
					},
				})

			case "/repositories/test-workspace/test-repo/pipelines":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{
							"uuid":         "pipeline-123",
							"build_number": 1,
							"state":        map[string]interface{}{"name": "COMPLETED"},
						},
					},
				})

			case "/repositories/test-workspace/test-repo/pipelines/pipeline-123/steps":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{"uuid": "step-123", "name": "Build"},
					},
				})

			case "/repositories/test-workspace/test-repo/pipelines/pipeline-123/steps/step-123/log":
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Build log content"))

			default:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{})
			}
		})
		defer cleanup()

		stdout, stderr, exitErr := testutil.RunCLI(t, []string{
			"bb", "scan",
			"--bitbucket", server.URL,
			"--email", "testuser",
			"--token", "testtoken",
			"--workspace", "test-workspace",
			// No --cookie, no --artifacts
		}, nil, 10*time.Second)

		assert.Nil(t, exitErr, "Scan should succeed without cookie and without artifacts")
		assert.False(t, userInfoCalled, "GetUserInfo should NOT be called without cookie")

		output := stdout + stderr
		t.Logf("Output:\n%s", output)
	})

	t.Run("WithCookie_WithoutArtifacts_CobraValidationFails", func(t *testing.T) {
		server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			t.Error("No API calls should be made - cobra should reject the command before execution")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		})
		defer cleanup()

		stdout, stderr, exitErr := testutil.RunCLI(t, []string{
			"bb", "scan",
			"--bitbucket", server.URL,
			"--email", "testuser",
			"--token", "testtoken",
			"--cookie", "test-cookie-value",
			"--workspace", "test-workspace",
			// Has --cookie but no --artifacts
		}, nil, 5*time.Second)

		// Cobra should reject this combination before any API calls
		assert.NotNil(t, exitErr, "Should fail due to cobra flag validation")

		output := stdout + stderr
		assert.Contains(t, output, "cookie", "Should mention cookie in error message")
		assert.Contains(t, output, "artifacts", "Should mention artifacts in error message")
		assert.Contains(t, output, "must all be set", "Should indicate both flags are required together")

		t.Logf("Output:\n%s", output)
	})

	t.Run("WithCookie_WithArtifacts_ValidationHappens", func(t *testing.T) {
		userInfoCalled := false

		server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			t.Logf("BitBucket Mock: %s %s", r.Method, r.URL.Path)

			switch r.URL.Path {
			case "/!api/2.0/user":
				// This endpoint SHOULD be called with both cookie and artifacts
				userInfoCalled = true
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"uuid":         "user-789",
					"display_name": "Test User With Cookie Auth",
				})

			case "/2.0/user":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"uuid":         "user-123",
					"display_name": "Test User",
				})

			case "/2.0/workspaces":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{"slug": "test-workspace", "name": "Test Workspace"},
					},
				})

			case "/repositories/test-workspace":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{"slug": "test-repo", "name": "Test Repo"},
					},
				})

			case "/repositories/test-workspace/test-repo/pipelines":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{
							"uuid":         "pipeline-123",
							"build_number": 1,
							"state":        map[string]interface{}{"name": "COMPLETED"},
						},
					},
				})

			case "/repositories/test-workspace/test-repo/pipelines/pipeline-123/steps":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{
						{"uuid": "step-123", "name": "Build"},
					},
				})

			case "/repositories/test-workspace/test-repo/pipelines/pipeline-123/steps/step-123/log":
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Build log content"))

			case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/steps/step-123/artifacts":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"values": []map[string]interface{}{},
				})

			default:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{})
			}
		})
		defer cleanup()

		stdout, stderr, exitErr := testutil.RunCLI(t, []string{
			"bb", "scan",
			"--bitbucket", server.URL,
			"--email", "testuser",
			"--token", "testtoken",
			"--cookie", "test-cookie-value",
			"--artifacts",
			"--workspace", "test-workspace",
			// Has BOTH --cookie AND --artifacts
		}, nil, 10*time.Second)

		assert.Nil(t, exitErr, "Scan should succeed with both cookie and artifacts")
		assert.True(t, userInfoCalled, "GetUserInfo MUST be called when both cookie and artifacts flags are set")

		output := stdout + stderr
		t.Logf("Output:\n%s", output)
	})

	t.Run("WithCookie_WithArtifacts_InvalidCookie_ShouldFail", func(t *testing.T) {
		userInfoCalled := false

		server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			t.Logf("BitBucket Mock: %s %s", r.Method, r.URL.Path)

			switch r.URL.Path {
			case "/!api/2.0/user":
				// This endpoint SHOULD be called and should return 401 for invalid cookie
				userInfoCalled = true
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"type": "error",
					"error": map[string]interface{}{
						"message": "Unauthorized",
					},
				})

			default:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{})
			}
		})
		defer cleanup()

		stdout, stderr, exitErr := testutil.RunCLI(t, []string{
			"bb", "scan",
			"--bitbucket", server.URL,
			"--email", "testuser",
			"--token", "testtoken",
			"--cookie", "invalid-cookie-value",
			"--artifacts",
			"--workspace", "test-workspace",
		}, nil, 10*time.Second)

		assert.NotNil(t, exitErr, "Scan should fail with invalid cookie when artifacts is enabled")
		assert.True(t, userInfoCalled, "GetUserInfo MUST be called to validate cookie")

		output := stdout + stderr
		assert.Contains(t, output, "Failed to get user info", "Should show cookie validation failure message")
		assert.Contains(t, output, "401", "Should show 401 unauthorized status")

		t.Logf("Output:\n%s", output)
	})
}
