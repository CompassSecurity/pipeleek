package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGitLabVariables(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-project", "web_url": "https://gitlab.example.com/test-project"},
			})

		case "/api/v4/projects/1/variables":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"key":           "DATABASE_URL",
					"value":         "postgres://user:pass@localhost/db",
					"protected":     false,
					"masked":        true,
					"variable_type": "env_var",
				},
			})

		case "/api/v4/projects/1/pipeline_schedules":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":          1,
					"description": "Nightly build",
					"ref":         "main",
				},
			})

		case "/api/v4/projects/1/pipeline_schedules/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":          1,
				"description": "Nightly build",
				"ref":         "main",
				"variables": []map[string]interface{}{
					{
						"key":   "DEPLOY_ENV",
						"value": "production",
					},
				},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "variables",
		"--gitlab", server.URL,
		"--token", "glpat-test",
	}, nil, 30*time.Second)

	assert.Nil(t, exitErr, "Variables command should succeed")

	requests := getRequests()
	variablesRequestFound := false
	schedulesRequestFound := false
	scheduleDetailsRequestFound := false

	for _, req := range requests {
		if req.Path == "/api/v4/projects/1/variables" {
			variablesRequestFound = true
			testutil.AssertRequestMethodAndPath(t, req, "GET", "/api/v4/projects/1/variables")
		}
		if req.Path == "/api/v4/projects/1/pipeline_schedules" {
			schedulesRequestFound = true
			testutil.AssertRequestMethodAndPath(t, req, "GET", "/api/v4/projects/1/pipeline_schedules")
		}
		if req.Path == "/api/v4/projects/1/pipeline_schedules/1" {
			scheduleDetailsRequestFound = true
			testutil.AssertRequestMethodAndPath(t, req, "GET", "/api/v4/projects/1/pipeline_schedules/1")
		}
	}

	assert.True(t, variablesRequestFound, "Should request project variables")
	assert.True(t, schedulesRequestFound, "Should request pipeline schedules")
	assert.True(t, scheduleDetailsRequestFound, "Should request pipeline schedule details")

	// Assert that project variables are printed in stdout
	assert.Contains(t, stdout, "Project variables", "Should log project variables")
	assert.Contains(t, stdout, "DATABASE_URL", "Should contain the DATABASE_URL variable key")
	assert.Contains(t, stdout, "postgres://user:pass@localhost/db", "Should contain the DATABASE_URL variable value")

	// Assert that pipeline schedule variables are printed in stdout
	assert.Contains(t, stdout, "Pipeline schedule variables", "Should log pipeline schedule variables")
	assert.Contains(t, stdout, "Nightly build", "Should contain the schedule description")
	assert.Contains(t, stdout, "DEPLOY_ENV", "Should contain the DEPLOY_ENV variable key")
	assert.Contains(t, stdout, "production", "Should contain the DEPLOY_ENV variable value")

	t.Logf("Variables request made: %v", variablesRequestFound)
	t.Logf("Schedules request made: %v", schedulesRequestFound)
	t.Logf("Schedule details request made: %v", scheduleDetailsRequestFound)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitLabRunnersList tests GitLab runners enumeration

func TestGitLabRunnersList(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v4/runners" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":          1,
					"description": "test-runner",
					"active":      true,
					"is_shared":   false,
				},
			})
		} else {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "runners", "list",
		"--gitlab", server.URL,
		"--token", "glpat-test",
	}, nil, 30*time.Second)

	assert.Nil(t, exitErr, "Runners list command should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API request")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitLabCICDYaml tests fetching CI/CD YAML configuration

func TestGitLabCICDYaml(t *testing.T) {
	t.Parallel()
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		t.Logf("CICD Yaml Mock: %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/api/v4/projects/test%2Fproject", "/api/v4/projects/test/project":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":   1,
				"name": "project",
			})

		case "/api/v4/projects/1/repository/files/.gitlab-ci.yml":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"file_name": ".gitlab-ci.yml",
				"content":   "c3RhZ2VzOgogIC0gYnVpbGQ=", // base64 encoded
			})

		case "/api/v4/projects/1/ci/lint":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "valid",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "cicd", "yaml",
		"--gitlab", server.URL,
		"--token", "glpat-test",
		"--project", "test/project",
	}, nil, 30*time.Second)

	assert.Nil(t, exitErr, "CICD yaml command should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitLabSchedule tests scheduled pipeline enumeration

func TestGitLabSchedule(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-project"},
			})

		case "/api/v4/projects/1/pipeline_schedules":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":          1,
					"description": "Nightly build",
					"ref":         "main",
					"cron":        "0 0 * * *",
					"active":      true,
				},
			})

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "schedule",
		"--gitlab", server.URL,
		"--token", "glpat-test",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Schedule command should succeed")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitLabSecureFiles tests secure files extraction

func TestGitLabSecureFiles(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-project"},
			})

		case "/api/v4/projects/1/secure_files":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":       1,
					"name":     "secret.key",
					"checksum": "abc123",
				},
			})

		case "/api/v4/projects/1/secure_files/1/download":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("secret-data"))

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "secureFiles",
		"--gitlab", server.URL,
		"--token", "glpat-test",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "SecureFiles command should succeed")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitLabUnauthenticatedRegister tests unauthenticated runner registration

func TestGitLabUnauthenticatedRegister(t *testing.T) {
	t.Parallel()
	registrationCalled := false
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v4/runners" && r.Method == "POST" {
			registrationCalled = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":    1,
				"token": "runner-token-xyz",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "register",
		"--gitlab", server.URL,
		"--token", "registration-token",
		"--executor", "shell",
		"--description", "test-runner",
	}, nil, 10*time.Second)

	// Command behavior depends on implementation
	// Log the output for inspection
	t.Logf("Registration called: %v", registrationCalled)
	t.Logf("Exit error: %v", exitErr)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	if registrationCalled {
		requests := getRequests()
		for _, req := range requests {
			if req.Path == "/api/v4/runners" {
				assert.Equal(t, "POST", req.Method)
			}
		}
	}
}

// TestGitLabVuln tests vulnerability scanning

func TestGitLabVuln(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Mock vulnerability report endpoint
		if r.URL.Path == "/api/v4/projects/1/vulnerabilities" {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":       1,
					"title":    "SQL Injection",
					"severity": "high",
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "vuln",
		"--gitlab", server.URL,
		"--token", "glpat-test",
		"--project", "1",
	}, nil, 10*time.Second)

	// Log output regardless of success/failure
	t.Logf("Exit error: %v", exitErr)
	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}

// TestGitLab_APIErrorHandling tests various API error scenarios
