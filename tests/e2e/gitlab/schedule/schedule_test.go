//go:build e2e

package e2e

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func setupMockGitLabScheduleAPI(t *testing.T) string {
	mux := http.NewServeMux()

	// Projects list endpoint
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"id":123,"name":"test-project","web_url":"https://gitlab.com/test-project"}
		]`))
	})

	// Pipeline schedules endpoint
	mux.HandleFunc("/api/v4/projects/123/pipeline_schedules", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{
				"id":1,
				"description":"Nightly build",
				"ref":"main",
				"cron":"0 2 * * *",
				"active":true,
				"variables":[
					{"key":"ENV","value":"production"},
					{"key":"DEBUG","value":"false"}
				]
			}
		]`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGLSchedule(t *testing.T) {
	apiURL := setupMockGitLabScheduleAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "schedule",
		"--gitlab", apiURL,
		"--token", "mock-token",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Schedule command should succeed")
	assert.Contains(t, stdout, "Fetched all schedules", "Should complete fetching schedules")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLSchedule_MissingToken(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "schedule",
		"--gitlab", "https://gitlab.com",
	}, nil, 5*time.Second)

	assert.NotNil(t, exitErr, "Should fail without token")
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing", "Should mention missing required configuration")
}

func TestGLSchedule_Unauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"401 Unauthorized"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	stdout, stderr, _ := testutil.RunCLI(t, []string{
		"gl", "schedule",
		"--gitlab", server.URL,
		"--token", "invalid-token",
	}, nil, 10*time.Second)

	// Command may handle errors gracefully
	assert.Contains(t, stdout+stderr, "401", "Should indicate unauthorized")
}
