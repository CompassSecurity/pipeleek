//go:build e2e

package tf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTFBasic tests the basic tf command functionality with a mock GitLab server
func TestTFBasic(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	tmpDir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/graphql" && r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "test-user/test-project") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":{"project":{"terraformStates":{"nodes":[{"name":"default"}]}}}}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"project":{"terraformStates":{"nodes":[]}}}}`))
			return
		}

		if strings.Contains(r.URL.Path, "/api/v4/projects") &&
			!strings.Contains(r.URL.Path, "/terraform/state") {
			projectsJSON := `[
{
"id": 1,
"path_with_namespace": "test-user/test-project",
"web_url": "http://localhost/test-user/test-project"
},
{
"id": 2,
"path_with_namespace": "test-user/no-tf-state",
"web_url": "http://localhost/test-user/no-tf-state"
}
]`
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total", "2")
			w.Header().Set("X-Total-Pages", "1")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(projectsJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/terraform/state/default") && r.Method == "GET" {
			if strings.Contains(r.URL.Path, "/projects/1/") {
				w.WriteHeader(http.StatusOK)
				tfState := `{"version": 4, "terraform_version": "1.0.0", "serial": 0}`
				w.Write([]byte(tfState))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message": "404 Not Found"}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "tf",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--output-dir", tmpDir,
		"--threads", "2",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	assert.Contains(t, stdout+stderr, "Found Terraform states")
	assert.Contains(t, stdout+stderr, "Downloaded Terraform state")
	assert.Contains(t, stdout+stderr, "Terraform state scan complete")

	statePath := filepath.Join(tmpDir, "1_default.tfstate")
	info, err := os.Stat(statePath)
	require.NoError(t, err, "state file should exist")
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

// TestTFNoState tests the tf command when no Terraform state is found
func TestTFNoState(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	tmpDir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/graphql" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"project":{"terraformStates":{"nodes":[]}}}}`))
			return
		}

		if strings.Contains(r.URL.Path, "/api/v4/projects") &&
			!strings.Contains(r.URL.Path, "/terraform/state") {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total", "0")
			w.Header().Set("X-Total-Pages", "1")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[]`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "tf",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--output-dir", tmpDir,
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	assert.Contains(t, stdout+stderr, "No Terraform states found")
}

// TestTFInvalidURL tests the tf command with invalid GitLab URL
func TestTFInvalidURL(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	tmpDir := t.TempDir()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "tf",
		"--gitlab", "not-a-valid-url",
		"--token", "test-token",
		"--output-dir", tmpDir,
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.NotNil(t, exitErr)
	assert.Contains(t, stdout+stderr, "Invalid GitLab URL")
}

// TestTFMissingToken tests the tf command without required token
func TestTFMissingToken(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	tmpDir := t.TempDir()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "tf",
		"--gitlab", "https://gitlab.example.com",
		"--output-dir", tmpDir,
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.NotNil(t, exitErr)
	assert.Contains(t, stdout+stderr, "required configuration missing")
}

// TestTFOutputDir tests that the tf command creates output directory if it doesn't exist
func TestTFOutputDir(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	tmpBase := t.TempDir()
	outputDir := filepath.Join(tmpBase, "nested", "output", "dir")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/graphql" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"project":{"terraformStates":{"nodes":[]}}}}`))
			return
		}

		if strings.Contains(r.URL.Path, "/api/v4/projects") &&
			!strings.Contains(r.URL.Path, "/terraform/state") {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total", "0")
			w.Header().Set("X-Total-Pages", "1")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "tf",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--output-dir", outputDir,
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	_, err := os.Stat(outputDir)
	require.NoError(t, err, "Output directory should be created")
}
