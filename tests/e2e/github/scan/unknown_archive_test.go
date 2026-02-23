//go:build e2e

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

// TestGitHubScan_UnknownArchive_BinaryWithSecrets tests that when encountering
// an unknown archive file type, the scanner extracts printable strings and scans them
func TestGitHubScan_UnknownArchive_BinaryWithSecrets(t *testing.T) {
	t.Parallel()
	// Create a binary file that is not a recognizable archive format
	// but contains embedded secrets (simulating a compiled binary or proprietary format)
	binaryData := []byte{
		// Binary header (PE/COFF simulation)
		0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Embedded secrets in printable format
		'D', 'A', 'T', 'A', 'B', 'A', 'S', 'E', '_', 'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D', '=',
		'S', 'u', 'p', 'e', 'r', 'S', 'e', 'c', 'r', 'e', 't', 'P', 'a', 's', 's', '1', '2', '3', '!',
		0x00, 0x00,
		// More binary data
		0xFF, 0xFE, 0xFD, 0xFC,
		// Another embedded secret
		'A', 'W', 'S', '_', 'A', 'C', 'C', 'E', 'S', 'S', '_', 'K', 'E', 'Y', '_', 'I', 'D', '=',
		'A', 'K', 'I', 'A', 'I', 'O', 'S', 'F', 'O', 'D', 'N', 'N', '7', 'E', 'X', 'A', 'M', 'P', 'L', 'E',
		0x00, 0xFF,
	}

	// Wrap the binary in a ZIP file (GitHub artifacts are always zips)
	var artifactZipBuf bytes.Buffer
	artifactZipWriter := zip.NewWriter(&artifactZipBuf)
	binaryFile, _ := artifactZipWriter.Create("app.bin")
	_, _ = binaryFile.Write(binaryData)
	_ = artifactZipWriter.Close()

	// Create empty logs zip
	var logsZipBuf bytes.Buffer

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (UnknownArchive): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/api/v3/user/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":        1,
					"name":      "test-repo",
					"full_name": "user/test-repo",
					"html_url":  "https://github.com/user/test-repo",
					"owner":     map[string]interface{}{"login": "user"},
				},
			})

		case "/api/v3/repos/user/test-repo/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{
						"id":            400,
						"name":          "binary-workflow",
						"status":        "completed",
						"display_title": "Binary Artifact Build",
						"html_url":      "https://github.com/user/test-repo/actions/runs/400",
						"repository": map[string]interface{}{
							"name":  "test-repo",
							"owner": map[string]interface{}{"login": "user"},
						},
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/400/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jobs":        []map[string]interface{}{},
				"total_count": 0,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/400/logs":
			w.Header().Set("Location", "http://"+r.Host+"/download/logs/400.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/logs/400.zip":
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(logsZipBuf.Bytes())

		case "/api/v3/repos/user/test-repo/actions/runs/400/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"artifacts": []map[string]interface{}{
					{
						"id":                   401,
						"name":                 "compiled-binary",
						"size_in_bytes":        len(artifactZipBuf.Bytes()),
						"archive_download_url": "http://" + r.Host + "/api/v3/repos/user/test-repo/actions/artifacts/401/zip",
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/artifacts/401/zip":
			w.Header().Set("Location", "http://"+r.Host+"/download/binary/401.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/binary/401.zip":
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(artifactZipBuf.Bytes())

		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "scan",
		"--github", server.URL,
		"--token", "ghp_test_token",
		"--owned",
		"--artifacts",
		"--log-level", "debug",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "Unknown archive scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 3, "Should make API requests")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify that string extraction was triggered for unknown archive type (within the zip)
	assert.Contains(t, output, "extracting strings", "Should log string extraction for unknown archive")

	// Verify secrets were extracted and detected from binary file
	assert.Contains(t, output, "SECRET", "Should detect secrets in binary file")

	// Verify specific secrets were found
	assert.Contains(t, output, "DATABASE_PASSWORD", "Should detect DATABASE_PASSWORD")
}
