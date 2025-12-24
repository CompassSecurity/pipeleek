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

// TestGitHubScan_UnknownArchive_MachoExecutable tests string extraction from Mach-O binary
func TestGitHubScan_UnknownArchive_MachoExecutable(t *testing.T) {

	// Create a Mach-O-like binary with embedded secrets
	var machoBinary bytes.Buffer

	// Mach-O magic bytes (64-bit)
	machoBinary.Write([]byte{0xCF, 0xFA, 0xED, 0xFE})

	// Mach-O header continuation
	machoBinary.Write([]byte{
		0x07, 0x00, 0x00, 0x01, // CPU type
		0x03, 0x00, 0x00, 0x00, // CPU subtype
		0x02, 0x00, 0x00, 0x00, // File type
	})

	// Embedded configuration
	machoBinary.WriteString("SENDGRID_API_KEY=SG.1234567890abcdefghijklmnopqrstuvwxyz0123456789")
	machoBinary.WriteByte(0x00)

	// More binary data
	machoBinary.Write([]byte{0xFF, 0xFE, 0xFD, 0xFC})

	// Embedded JWT secret
	machoBinary.WriteString("JWT_SECRET=supersecretjwtkeyvalue123456789012345678901234567890")
	machoBinary.WriteByte(0x00)

	// Wrap in ZIP
	var artifactZipBuf bytes.Buffer
	artifactZipWriter := zip.NewWriter(&artifactZipBuf)
	machoFile, _ := artifactZipWriter.Create("macos-app")
	_, _ = machoFile.Write(machoBinary.Bytes())
	_ = artifactZipWriter.Close()

	var logsZipBuf bytes.Buffer

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (Macho): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/api/v3/user/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-repo", "full_name": "user/test-repo", "owner": map[string]interface{}{"login": "user"}},
			})

		case "/api/v3/repos/user/test-repo/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{
						"id":          500,
						"name":        "macho-workflow",
						"status":      "completed",
						"html_url":    "https://github.com/user/test-repo/actions/runs/500",
						"repository":  map[string]interface{}{"name": "test-repo", "owner": map[string]interface{}{"login": "user"}},
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/500/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jobs": []map[string]interface{}{}, "total_count": 0})

		case "/api/v3/repos/user/test-repo/actions/runs/500/logs":
			w.Header().Set("Location", "http://"+r.Host+"/download/logs/500.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/logs/500.zip":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(logsZipBuf.Bytes())

		case "/api/v3/repos/user/test-repo/actions/runs/500/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"artifacts": []map[string]interface{}{
					{
						"id":                   501,
						"name":                 "macos-app",
						"size_in_bytes":        artifactZipBuf.Len(),
						"archive_download_url": "http://" + r.Host + "/api/v3/repos/user/test-repo/actions/artifacts/501/zip",
					},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/artifacts/501/zip":
			w.Header().Set("Location", "http://"+r.Host+"/download/macho/501.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/macho/501.zip":
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
		"--log-level", "trace",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "Mach-O binary scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 3, "Should make API requests")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify string extraction was used
	assert.Contains(t, output, "extracting strings", "Should extract strings from Mach-O binary")

	// Verify secrets were detected
	assert.Contains(t, output, "SECRET", "Should detect secrets")
	assert.Contains(t, output, "SENDGRID_API_KEY", "Should detect SendGrid API key")
}

// TestGitHubScan_UnknownArchive_ProprietaryFormat tests handling of completely unknown format
func TestGitHubScan_UnknownArchive_ProprietaryFormat(t *testing.T) {

	// Create a proprietary binary format with magic bytes and embedded secrets
	var proprietaryBinary bytes.Buffer

	// Custom magic bytes
	proprietaryBinary.Write([]byte{0xDE, 0xAD, 0xC0, 0xDE})

	// Format version
	proprietaryBinary.Write([]byte{0x01, 0x00, 0x00, 0x00})

	// Embedded secrets
	proprietaryBinary.WriteString("STRIPE_SECRET_KEY=sk_live_51ABCD" + "EFghijklmnopqrstuvwxyz0123456789ABCDEF")
	proprietaryBinary.WriteByte(0x00)

	// More custom data
	proprietaryBinary.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE})

	// Another secret
	proprietaryBinary.WriteString("WEBHOOK_SECRET=whsec_abcdefghijklmnopqrstuvwxyz1234567890")
	proprietaryBinary.WriteByte(0x00)

	// Wrap in ZIP
	var artifactZipBuf bytes.Buffer
	artifactZipWriter := zip.NewWriter(&artifactZipBuf)
	customFile, _ := artifactZipWriter.Create("custom.dat")
	_, _ = customFile.Write(proprietaryBinary.Bytes())
	_ = artifactZipWriter.Close()

	var logsZipBuf bytes.Buffer

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("GitHub Mock (Proprietary): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/api/v3/user/repos":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "test-repo", "full_name": "user/test-repo", "owner": map[string]interface{}{"login": "user"}},
			})

		case "/api/v3/repos/user/test-repo/actions/runs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"workflow_runs": []map[string]interface{}{
					{"id": 600, "name": "custom-format", "status": "completed", "html_url": "https://github.com/user/test-repo/actions/runs/600", "repository": map[string]interface{}{"name": "test-repo", "owner": map[string]interface{}{"login": "user"}}},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/runs/600/jobs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jobs": []map[string]interface{}{}, "total_count": 0})

		case "/api/v3/repos/user/test-repo/actions/runs/600/logs":
			w.Header().Set("Location", "http://"+r.Host+"/download/logs/600.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/logs/600.zip":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(logsZipBuf.Bytes())

		case "/api/v3/repos/user/test-repo/actions/runs/600/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"artifacts": []map[string]interface{}{
					{"id": 601, "name": "custom.dat", "size_in_bytes": artifactZipBuf.Len(), "archive_download_url": "http://" + r.Host + "/api/v3/repos/user/test-repo/actions/artifacts/601/zip"},
				},
				"total_count": 1,
			})

		case "/api/v3/repos/user/test-repo/actions/artifacts/601/zip":
			w.Header().Set("Location", "http://"+r.Host+"/download/custom/601.zip")
			w.WriteHeader(http.StatusFound)

		case "/download/custom/601.zip":
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

	assert.Nil(t, exitErr, "Proprietary format scan should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify string extraction was used
	assert.Contains(t, output, "extracting strings", "Should extract strings from proprietary format")

	// Verify secrets were detected
	assert.Contains(t, output, "SECRET", "Should detect secrets")
	assert.Contains(t, output, "Stripe", "Should detect Stripe secret key")
}
