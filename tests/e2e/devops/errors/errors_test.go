package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestAzureDevOpsScan_MissingToken(t *testing.T) {
	t.Parallel()
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"ad", "scan",
		"--devops", "https://dev.azure.com",
		"--organization", "myorg",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)
}

// TestAzureDevOpsScan_WithLogs tests scanning pipeline logs with secrets

func TestAzureDevOpsScan_Unauthorized(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("Azure DevOps Mock (Unauthorized): %s %s", r.Method, r.URL.Path)

		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Unauthorized",
		})
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"ad", "scan",
		"--devops", server.URL,
		"--token", "invalid-token",
		"--username", "testuser",
		"--organization", "myorg",
	}, nil, 10*time.Second)

	// Might exit with error or complete with logged errors
	output := stdout + stderr
	assert.Contains(t, output, "401", "Should log 401 error")
	t.Logf("Exit error: %v", exitErr)
	t.Logf("Output:\n%s", output)
}

// TestAzureDevOpsScan_Project tests scanning specific project
