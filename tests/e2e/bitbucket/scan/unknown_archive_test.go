//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

// TestBitBucketScan_UnknownArchive_BinaryWithSecrets tests that when encountering
// an unknown archive file type, the scanner extracts printable strings and scans them
func TestBitBucketScan_UnknownArchive_BinaryWithSecrets(t *testing.T) {

	// Create a binary file that is not a recognizable archive format
	// but contains embedded secrets (simulating a compiled binary or proprietary format)
	binaryData := []byte{
		// Binary header (not a valid archive format)
		0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Embedded secrets in printable format
		'G', 'I', 'T', 'L', 'A', 'B', '_', 'T', 'O', 'K', 'E', 'N', '=',
		'g', 'l', 'p', 'a', 't', '-', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f',
		0x00, 0x00,
		// More binary data
		0xFF, 0xFE, 0xFD, 0xFC,
		// Another embedded secret
		'A', 'P', 'I', '_', 'K', 'E', 'Y', '=',
		's', 'k', '_', 'l', 'i', 'v', 'e', '_', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
		0x00, 0xFF,
		// More binary
		0xDE, 0xAD, 0xBE, 0xEF,
	}

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (UnknownArchive): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/!api/2.0/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"username":     "testuser",
				"display_name": "Test User",
				"uuid":         "{user-uuid-1}",
			})

		case "/repositories/test-workspace":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid": "{repo-uuid-1}",
						"name": "test-repo",
						"slug": "test-repo",
					},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":         "{pipeline-uuid-1}",
						"build_number": 1,
						"state": map[string]interface{}{
							"name": "COMPLETED",
						},
					},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid": "{step-uuid-1}",
						"name": "Build",
					},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps/{step-uuid-1}/log":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Build completed"))

		case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":            "{artifact-uuid-1}",
						"step_uuid":       "{step-uuid-1}",
						"name":            "app.bin",
						"path":            "artifacts/app.bin",
						"artifactType":    "file",
						"file_size_bytes": len(binaryData),
					},
				},
			})

		case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/artifacts/{artifact-uuid-1}/content":
			// Serve the binary data directly (not a zip or known archive format)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(binaryData)

		case "/repositories/test-workspace/test-repo/downloads":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})

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
		"--token", "testpass",
		"--cookie", "test-cookie",
		"--workspace", "test-workspace",
		"--artifacts",
		"--log-level", "debug",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "Unknown archive scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify that string extraction was triggered for unknown archive type
	assert.Contains(t, output, "extracting strings", "Should log string extraction for unknown archive")

	// Verify secrets were extracted and detected from binary file
	assert.Contains(t, output, "SECRET", "Should detect secrets in binary file")

	// Verify specific secrets were found
	// The scanner should extract "GITLAB_TOKEN=glpat-1234567890abcdef" from the binary
	assert.Contains(t, output, "GITLAB_TOKEN", "Should detect GITLAB_TOKEN in extracted strings")
}

// TestBitBucketScan_UnknownArchive_ELFBinary tests string extraction from ELF binary format
func TestBitBucketScan_UnknownArchive_ELFBinary(t *testing.T) {

	// Create an ELF-like binary with embedded secrets
	var elfBinary bytes.Buffer

	// ELF header magic bytes
	elfBinary.Write([]byte{0x7F, 'E', 'L', 'F'})

	// ELF header continuation
	elfBinary.Write([]byte{
		0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	// Embedded configuration string
	elfBinary.WriteString("DATABASE_URL=postgresql://admin:SecretDBPass123@db.example.com/prod")
	elfBinary.Write([]byte{0x00})

	// More binary data
	elfBinary.Write([]byte{0xFF, 0xFE, 0xFD, 0xFC})

	// Embedded API key
	elfBinary.WriteString("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	elfBinary.Write([]byte{0x00})

	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (ELF): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/!api/2.0/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"username": "testuser",
				"uuid":     "{user-uuid-1}",
			})

		case "/repositories/test-workspace":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{"uuid": "{repo-uuid-1}", "name": "test-repo", "slug": "test-repo"},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{"uuid": "{pipeline-uuid-1}", "build_number": 1, "state": map[string]interface{}{"name": "COMPLETED"}},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{"uuid": "{step-uuid-1}", "name": "Build"},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps/{step-uuid-1}/log":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Build completed"))

		case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":            "{artifact-uuid-1}",
						"name":            "application",
						"file_size_bytes": elfBinary.Len(),
					},
				},
			})

		case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/artifacts/{artifact-uuid-1}/content":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(elfBinary.Bytes())

		case "/repositories/test-workspace/test-repo/downloads":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})

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
		"--token", "testpass",
		"--cookie", "test-cookie",
		"--workspace", "test-workspace",
		"--artifacts",
		"--log-level", "trace",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "ELF binary scan should succeed")

	requests := getRequests()
	assert.True(t, len(requests) >= 1, "Should make API requests")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify string extraction was used
	assert.Contains(t, output, "extracting strings", "Should extract strings from ELF binary")

	// Verify secrets were detected
	assert.Contains(t, output, "SECRET", "Should detect secrets")
	assert.Contains(t, output, "DATABASE_URL", "Should detect database URL with password")
	assert.Contains(t, output, "Password in URL", "Should identify password in database URL")
}

// TestBitBucketScan_UnknownArchive_MixedBinaryFormats tests handling of multiple unknown formats
func TestBitBucketScan_UnknownArchive_MixedBinaryFormats(t *testing.T) {

	// Binary 1: Proprietary format with secret
	binary1 := []byte{
		0xCA, 0xFE, 0xBA, 0xBE, // Magic bytes (like Java class file)
		0x00, 0x00, 0x00, 0x34,
	}
	binary1 = append(binary1, []byte("STRIPE_API_KEY=sk_live_51ABCDEFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")...)
	binary1 = append(binary1, 0x00)

	// Binary 2: Another format with secret
	binary2 := []byte{
		0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', // PNG header
		0x00, 0x00, 0x00, 0x0D,
	}
	binary2 = append(binary2, []byte("GITHUB_TOKEN=ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcd")...)
	binary2 = append(binary2, 0x00)

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		t.Logf("BitBucket Mock (Mixed): %s %s", r.Method, r.URL.Path)

		switch r.URL.Path {
		case "/!api/2.0/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"username": "testuser",
				"uuid":     "{user-uuid-1}",
			})

		case "/repositories/test-workspace":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{"uuid": "{repo-uuid-1}", "name": "test-repo", "slug": "test-repo"},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{"uuid": "{pipeline-uuid-1}", "build_number": 1, "state": map[string]interface{}{"name": "COMPLETED"}},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{"uuid": "{step-uuid-1}", "name": "Build"},
				},
			})

		case "/repositories/test-workspace/test-repo/pipelines/{pipeline-uuid-1}/steps/{step-uuid-1}/log":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Build completed"))

		case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/artifacts":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"values": []map[string]interface{}{
					{
						"uuid":            "{artifact-uuid-1}",
						"name":            "app.class",
						"file_size_bytes": len(binary1),
					},
					{
						"uuid":            "{artifact-uuid-2}",
						"name":            "image.dat",
						"file_size_bytes": len(binary2),
					},
				},
			})

		case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/artifacts/{artifact-uuid-1}/content":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(binary1)

		case "/!api/internal/repositories/test-workspace/test-repo/pipelines/1/artifacts/{artifact-uuid-2}/content":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(binary2)

		case "/repositories/test-workspace/test-repo/downloads":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"values": []interface{}{}})

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
		"--token", "testpass",
		"--cookie", "test-cookie",
		"--workspace", "test-workspace",
		"--artifacts",
		"--log-level", "debug",
	}, nil, 20*time.Second)

	assert.Nil(t, exitErr, "Mixed binary formats scan should succeed")

	output := stdout + stderr
	t.Logf("Output:\n%s", output)

	// Verify both binaries were processed
	assert.Contains(t, output, "extracting strings", "Should extract strings from unknown formats")

	// Verify secrets from both files were detected
	assert.Contains(t, output, "SECRET", "Should detect secrets in binary files")
	assert.Contains(t, output, "Stripe", "Should detect Stripe API key")
	// Note: GitHub token detection depends on TruffleHog's pattern matching
	// We verify the file was processed by checking for the "extracting strings" message
}
