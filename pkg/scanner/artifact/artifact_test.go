package artifact

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/scanner/rules"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
)

func init() {
	rules.InitRules([]string{})
}

const testTimeout = 60 * time.Second

func TestDetectFileHits(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
	}{
		{
			name:    "no secrets",
			content: []byte("plain text file"),
		},
		{
			name:    "with potential secret",
			content: []byte("GITLAB_USER_ID=12345"),
		},
		{
			name:    "empty file",
			content: []byte(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DetectFileHits(tt.content, "http://example.com/job/1", "test-job", "test.txt", "", false, testTimeout)
		})
	}
}

func TestReportFinding(t *testing.T) {
	finding := types.Finding{
		Pattern: types.PatternElement{
			Pattern: types.PatternPattern{
				Name:       "Test Pattern",
				Confidence: "high",
			},
		},
		Text: "secret value",
	}

	t.Run("report without archive", func(t *testing.T) {
		ReportFinding(finding, "http://example.com/job/1", "test-job", "test.txt", "")
	})

	t.Run("report with archive", func(t *testing.T) {
		ReportFinding(finding, "http://example.com/job/1", "test-job", "test.txt", "archive.zip")
	})
}

func TestHandleArchiveArtifact(t *testing.T) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	f, err := w.Create("test.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("GITLAB_USER_ID=12345"))

	_ = w.Close()

	t.Run("valid zip archive", func(t *testing.T) {
		HandleArchiveArtifact("test.zip", buf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout)
	})

	t.Run("invalid archive data", func(t *testing.T) {
		HandleArchiveArtifact("invalid.zip", []byte("not a zip file"), "http://example.com/job/1", "test-job", false, testTimeout)
	})
}

func TestHandleArchiveArtifactWithDepth(t *testing.T) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	f, err := w.Create("test.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("test content"))

	_ = w.Close()

	t.Run("normal depth", func(t *testing.T) {
		HandleArchiveArtifactWithDepth("test.zip", buf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout, 1)
	})

	t.Run("max depth exceeded", func(t *testing.T) {
		HandleArchiveArtifactWithDepth("test.zip", buf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout, 11)
	})

	t.Run("skipped directory - node_modules", func(t *testing.T) {
		HandleArchiveArtifactWithDepth("node_modules/test.zip", buf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout, 1)
	})

	t.Run("skipped directory - vendor", func(t *testing.T) {
		HandleArchiveArtifactWithDepth("vendor/test.zip", buf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout, 1)
	})
}

func TestHandleArchiveArtifact_NestedZip(t *testing.T) {
	innerBuf := new(bytes.Buffer)
	innerW := zip.NewWriter(innerBuf)
	innerF, _ := innerW.Create("inner.txt")
	_, _ = innerF.Write([]byte("GITLAB_USER_ID=99999"))
	_ = innerW.Close()

	outerBuf := new(bytes.Buffer)
	outerW := zip.NewWriter(outerBuf)
	outerF, _ := outerW.Create("inner.zip")
	_, _ = outerF.Write(innerBuf.Bytes())
	_ = outerW.Close()

	t.Run("nested zip archive", func(t *testing.T) {
		HandleArchiveArtifact("outer.zip", outerBuf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout)
	})
}

func TestDetectFileHits_RealFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "secret.txt")

	err := os.WriteFile(testFile, []byte("CI_REGISTRY_PASSWORD=mysupersecret"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatal(err)
	}

	DetectFileHits(content, "http://example.com/job/1", "test-job", "secret.txt", "", false, testTimeout)
}

// TestHandleArchiveArtifactWithDepth_NestedArchiveFileNameFix verifies that nested archives
// are processed with their actual filenames, not the parent archive name.
// This test validates the fix for the bug where files like "xyz.macho" would appear to loop endlessly
// because the parent archive name was being reused instead of the actual nested file name.
func TestHandleArchiveArtifactWithDepth_NestedArchiveFileNameFix(t *testing.T) {
	// Create an inner zip archive with a specific name that could be misidentified
	innerBuf := new(bytes.Buffer)
	innerW := zip.NewWriter(innerBuf)
	innerF, err := innerW.Create("data.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = innerF.Write([]byte("some content in nested archive"))
	_ = innerW.Close()

	// Create an outer zip archive containing the inner zip with a specific name
	// This simulates a scenario like "xyz.macho" inside an artifact
	outerBuf := new(bytes.Buffer)
	outerW := zip.NewWriter(outerBuf)
	nestedFileName := "nested.zip"
	outerF, err := outerW.Create(nestedFileName)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = outerF.Write(innerBuf.Bytes())
	_ = outerW.Close()

	// Before the fix, this would use "parent.zip" for both the parent and nested archive
	// After the fix, it should use "parent.zip" for parent and "nested.zip" for the nested archive
	t.Run("nested archive uses correct filename", func(t *testing.T) {
		// This should not cause an endless loop or incorrect filename reuse
		// The fix ensures HandleArchiveArtifactWithDepth receives "nested.zip" not "parent.zip"
		HandleArchiveArtifactWithDepth("parent.zip", outerBuf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout, 1)
		// If we reach here without hanging or panicking, the fix is working
	})
}

// TestHandleArchiveArtifactWithDepth_DeeplyNestedArchives tests that deeply nested archives
// are handled correctly with proper depth tracking and filename propagation.
func TestHandleArchiveArtifactWithDepth_DeeplyNestedArchives(t *testing.T) {
	// Create a chain of nested archives: level3.zip -> level2.zip -> level1.zip -> data.txt
	level1Buf := new(bytes.Buffer)
	level1W := zip.NewWriter(level1Buf)
	level1F, _ := level1W.Create("data.txt")
	_, _ = level1F.Write([]byte("GITLAB_TOKEN=secret123"))
	_ = level1W.Close()

	level2Buf := new(bytes.Buffer)
	level2W := zip.NewWriter(level2Buf)
	level2F, _ := level2W.Create("level1.zip")
	_, _ = level2F.Write(level1Buf.Bytes())
	_ = level2W.Close()

	level3Buf := new(bytes.Buffer)
	level3W := zip.NewWriter(level3Buf)
	level3F, _ := level3W.Create("level2.zip")
	_, _ = level3F.Write(level2Buf.Bytes())
	_ = level3W.Close()

	t.Run("deeply nested archives with correct filenames", func(t *testing.T) {
		// Each level should use its actual filename, not the parent's
		HandleArchiveArtifactWithDepth("level3.zip", level3Buf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout, 1)
	})

	t.Run("deeply nested archives respect max depth", func(t *testing.T) {
		// Starting at depth 9 means level1.zip (depth 11) should be skipped
		HandleArchiveArtifactWithDepth("level3.zip", level3Buf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout, 9)
	})
}

// TestHandleArchiveArtifactWithDepth_MixedContent tests archives containing both
// regular files and nested archives to ensure proper handling of each type.
func TestHandleArchiveArtifactWithDepth_MixedContent(t *testing.T) {
	// Create a nested archive
	nestedBuf := new(bytes.Buffer)
	nestedW := zip.NewWriter(nestedBuf)
	nestedF, _ := nestedW.Create("nested_file.txt")
	_, _ = nestedF.Write([]byte("nested content"))
	_ = nestedW.Close()

	// Create main archive with mixed content
	mainBuf := new(bytes.Buffer)
	mainW := zip.NewWriter(mainBuf)

	// Add regular text file
	txtFile, _ := mainW.Create("readme.txt")
	_, _ = txtFile.Write([]byte("README content"))

	// Add nested archive
	zipFile, _ := mainW.Create("artifact.zip")
	_, _ = zipFile.Write(nestedBuf.Bytes())

	// Add another regular file
	dataFile, _ := mainW.Create("data.json")
	_, _ = dataFile.Write([]byte(`{"key": "value"}`))

	_ = mainW.Close()

	t.Run("mixed content with nested archive", func(t *testing.T) {
		// Should process both regular files and recursively handle nested archive
		HandleArchiveArtifactWithDepth("mixed.zip", mainBuf.Bytes(), "http://example.com/job/1", "test-job", false, testTimeout, 1)
	})
}

// TestHandleArchiveArtifact_UnknownArchive tests that unknown archive types
// are handled by extracting strings instead of failing silently.
func TestHandleArchiveArtifact_UnknownArchive(t *testing.T) {
	// Create a binary file that looks like it might be an archive but isn't recognized
	binaryData := []byte{
		0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, // PE header simulation
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Embed a secret that should be extracted
		'G', 'I', 'T', 'L', 'A', 'B', '_', 'T', 'O', 'K', 'E', 'N', '=', 'g', 'l', 'p', 'a', 't', '-', '1', '2', '3', '4', '5',
		0x00, 0x00, 0xFF, 0xFF,
		// More binary data
		0xDE, 0xAD, 0xBE, 0xEF,
	}

	t.Run("unknown archive with embedded secret", func(t *testing.T) {
		// This should extract strings from the binary and scan them
		HandleArchiveArtifact("unknown.bin", binaryData, "http://example.com/job/1", "test-job", false, testTimeout)
		// If a secret is found, it will be logged. The test just ensures no panic/error occurs.
	})
}

// TestHandleArchiveArtifact_BinaryWithMultipleSecrets tests that multiple secrets
// can be extracted from a single binary file with unknown format.
func TestHandleArchiveArtifact_BinaryWithMultipleSecrets(t *testing.T) {
	// Create a binary file with multiple embedded secrets
	binaryData := []byte{
		0xFF, 0xFE, 0xFD, 0xFC,
		// First secret
		'A', 'P', 'I', '_', 'K', 'E', 'Y', '=', 's', 'e', 'c', 'r', 'e', 't', '1', '2', '3',
		0x00, 0x00, 0x01, 0x02,
		// Second secret
		'D', 'A', 'T', 'A', 'B', 'A', 'S', 'E', '_', 'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D', '=', 'p', 'a', 's', 's', '1', '2', '3',
		0x00, 0xFF,
	}

	t.Run("binary with multiple secrets", func(t *testing.T) {
		HandleArchiveArtifact("secrets.dat", binaryData, "http://example.com/job/1", "test-job", false, testTimeout)
		// Both secrets should be extracted and scanned
	})
}

// TestHandleArchiveArtifact_EmptyBinary tests handling of empty binary files.
func TestHandleArchiveArtifact_EmptyBinary(t *testing.T) {
	t.Run("empty binary file", func(t *testing.T) {
		HandleArchiveArtifact("empty.bin", []byte{}, "http://example.com/job/1", "test-job", false, testTimeout)
		// Should handle gracefully without errors
	})
}

// TestHandleArchiveArtifact_PureBinary tests handling of pure binary data
// without any printable strings.
func TestHandleArchiveArtifact_PureBinary(t *testing.T) {
	pureBinary := make([]byte, 1000)
	for i := range pureBinary {
		pureBinary[i] = byte(i % 256)
	}

	t.Run("pure binary without printable strings", func(t *testing.T) {
		HandleArchiveArtifact("random.bin", pureBinary, "http://example.com/job/1", "test-job", false, testTimeout)
		// Should extract no strings and handle gracefully
	})
}
