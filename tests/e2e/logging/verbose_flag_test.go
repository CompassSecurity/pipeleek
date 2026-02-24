package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

// TestVerboseFlag_Default checks that running any command without -v uses info log level
func TestVerboseFlag_Default(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "test-token",
	}, nil, 6*time.Second)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Log level set to info (default)", "Default log level should be info")
}

// TestVerboseFlag_Short sets log level to debug with -v
func TestVerboseFlag_Short(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "test-token",
		"-v",
	}, nil, 6*time.Second)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Log level set to debug (-v)", "Short -v should set debug level")
}

// TestVerboseFlag_LongDebug sets log level to debug with --log-level=debug
func TestVerboseFlag_LongDebug(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--log-level=debug",
	}, nil, 6*time.Second)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Log level set to debug (explicit)", "--log-level=debug should set debug level")
}

// TestVerboseFlag_LongWarn sets log level to warn with --log-level=warn
func TestVerboseFlag_LongWarn(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--log-level=warn",
	}, nil, 6*time.Second)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Log level set to warn (explicit)", "--log-level=warn should set warn level")
}

// TestVerboseFlag_LongTrace sets log level to trace with --log-level=trace
func TestVerboseFlag_LongTrace(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--log-level=trace",
	}, nil, 6*time.Second)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Log level set to trace (explicit)", "--log-level=trace should set trace level")
}

// TestVerboseFlag_Invalid sets log level to info with invalid value
func TestVerboseFlag_Invalid(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--log-level=invalid",
	}, nil, 6*time.Second)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Invalid log level, defaulting to info", "Invalid log-level value should default to info")
}

// TestVerboseFlag_ErrorLevel sets log level to error with --log-level=error
func TestVerboseFlag_ErrorLevel(t *testing.T) {
	t.Parallel()
	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "scan",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--log-level=error",
	}, nil, 6*time.Second)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Log level set to error (explicit)", "--log-level=error should set error level")
}
