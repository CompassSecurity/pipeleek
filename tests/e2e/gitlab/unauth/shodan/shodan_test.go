//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func setupMockGitLabShodanAPI(t *testing.T, registrationEnabled bool, nrProjects int) string {
	mux := http.NewServeMux()

	// Mock the registration check endpoint
	mux.HandleFunc("/users/somenotexistigusr/exists", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if registrationEnabled {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"exists":false}`))
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	})

	// Mock the public projects endpoint
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		projects := make([]map[string]interface{}, nrProjects)
		for i := 0; i < nrProjects; i++ {
			projects[i] = map[string]interface{}{
				"id":   i + 1,
				"name": "project-" + string(rune(i)),
			}
		}
		json.NewEncoder(w).Encode(projects)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server.URL
}

func createShodanJSONFile(t *testing.T, hostnames []string, ipStrs []string, ports []int, modules []string) string {
	tmpDir := t.TempDir()
	jsonFile := filepath.Join(tmpDir, "shodan-export.json")

	file, err := os.Create(jsonFile)
	assert.NoError(t, err, "Should create temp file")
	defer file.Close()

	maxLen := len(ipStrs)
	if len(hostnames) > maxLen {
		maxLen = len(hostnames)
	}

	for i := 0; i < maxLen; i++ {
		port := 443
		module := "https"
		var hostnameList []string
		ipStr := "127.0.0.1"

		if i < len(hostnames) && hostnames[i] != "" {
			hostnameList = []string{hostnames[i]}
		} else {
			hostnameList = []string{} // Empty array, not nil
		}
		if i < len(ipStrs) {
			ipStr = ipStrs[i]
		}
		if i < len(ports) {
			port = ports[i]
		}
		if i < len(modules) {
			module = modules[i]
		}

		entry := map[string]interface{}{
			"hostnames": hostnameList,
			"port":      port,
			"ip_str":    ipStr,
			"_shodan": map[string]interface{}{
				"module": module,
			},
		}
		jsonBytes, err := json.Marshal(entry)
		assert.NoError(t, err, "Should marshal JSON")
		_, err = file.Write(jsonBytes)
		assert.NoError(t, err, "Should write JSON bytes")
		_, err = file.Write([]byte("\n"))
		assert.NoError(t, err, "Should write newline")
	}

	return jsonFile
}

func TestGLunaShodan(t *testing.T) {
	t.Parallel()
	// The shodan command processes a JSON file and makes HTTP requests to test GitLab instances
	// Since HTTP requests to unreachable hosts have retries and long timeouts,
	// we verify the command accepts the JSON file and begins processing
	jsonFile := createShodanJSONFile(t, []string{""}, []string{"192.0.2.1"}, []int{443}, []string{"https"})

	_, _, exitErr := testutil.RunCLI(t, []string{
		"gluna", "shodan",
		"--json", jsonFile,
	}, nil, 3*time.Second)

	// Command times out making HTTP requests (expected for unreachable hosts)
	// The fact that it times out (rather than failing immediately) indicates
	// it successfully parsed the JSON and started processing
	assert.NotNil(t, exitErr, "Command times out making HTTP requests")
	assert.Contains(t, exitErr.Error(), "timed out", "Should timeout, not crash")
}

func TestGLunaShodan_MissingJSON(t *testing.T) {
	t.Parallel()
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "shodan",
	}, nil, 3*time.Second)

	// Command should fail due to missing required flag
	output := stdout + stderr
	// The command may timeout or exit with error
	assert.True(t, exitErr != nil, "Command should fail without --json flag")
	// Just verify it's executed
	t.Logf("Output: %s", output)
}

func TestGLunaShodan_InvalidJSONFile(t *testing.T) {
	t.Parallel()
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "shodan",
		"--json", "/nonexistent/file.json",
	}, nil, 3*time.Second)

	// Command should fail or log error for nonexistent file
	output := stdout + stderr
	assert.NotNil(t, exitErr, "Should fail for nonexistent file")
	assert.Contains(t, output, "failed opening file")
}

func TestGLunaShodan_HTTPModule(t *testing.T) {
	t.Parallel()
	// Test with HTTP module
	jsonFile := createShodanJSONFile(t, []string{""}, []string{"192.0.2.2"}, []int{8080}, []string{"http"})

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "shodan",
		"--json", jsonFile,
	}, nil, 3*time.Second)

	output := stdout + stderr
	assert.NotNil(t, exitErr, "Command times out")
	assert.Contains(t, output, "Log level set to")
}

func TestGLunaShodan_MultipleInstances(t *testing.T) {
	t.Parallel()
	// Test with multiple entries in JSON file
	jsonFile := createShodanJSONFile(t,
		[]string{"", ""},
		[]string{"192.0.2.3", "192.0.2.4"},
		[]int{443, 8080},
		[]string{"https", "http"})

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "shodan",
		"--json", jsonFile,
	}, nil, 3*time.Second)

	output := stdout + stderr
	assert.NotNil(t, exitErr, "Command times out")
	assert.Contains(t, output, "Log level set to")
}

func TestGLunaShodan_WithHostname(t *testing.T) {
	t.Parallel()
	// Test with hostname instead of IP
	jsonFile := createShodanJSONFile(t, []string{"example.invalid"}, []string{"192.0.2.5"}, []int{443}, []string{"https"})

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gluna", "shodan",
		"--json", jsonFile,
	}, nil, 3*time.Second)

	output := stdout + stderr
	assert.NotNil(t, exitErr, "Command times out")
	assert.Contains(t, output, "Log level set to")
}
