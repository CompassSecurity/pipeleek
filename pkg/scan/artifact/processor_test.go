package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/h2non/filetype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessSingleFileExecutableAndUTF8(t *testing.T) {
	for _, container := range []string{"standalone", "zip", "tar"} {
		for _, binary := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/binary=%v", container, binary), func(t *testing.T) {
				secret := fmt.Sprintf("credential-%s-%v", container, binary)
				content := []byte("CI_REGISTRY_PASSWORD=" + secret + "\n")
				name := "config.env"
				if binary {
					name = "program"
					header := make([]byte, 64)
					copy(header, "\x7fELF")
					content = append(header, content...)
					kind, err := filetype.Match(content)
					require.NoError(t, err)
					require.Equal(t, "elf", kind.Extension, "fixture must match the real ELF detector")
				} else {
					secret += "-p\u00e4ssw\u00f6rd"
					content = []byte("CI_REGISTRY_PASSWORD=" + secret + "\n")
				}
				expectedFile := name
				secondSecret := "after-" + secret
				switch container {
				case "zip":
					var buf bytes.Buffer
					w := zip.NewWriter(&buf)
					for _, file := range []struct {
						name    string
						content []byte
					}{
						{name, content}, {"after.env", []byte("CI_REGISTRY_PASSWORD=" + secondSecret + "\n")},
					} {
						f, err := w.Create(file.name)
						require.NoError(t, err)
						_, err = f.Write(file.content)
						require.NoError(t, err)
					}
					require.NoError(t, w.Close())
					content, name = buf.Bytes(), "bundle.zip"
				case "tar":
					var buf bytes.Buffer
					w := tar.NewWriter(&buf)
					for _, file := range []struct {
						name    string
						content []byte
					}{
						{name, content}, {"after.env", []byte("CI_REGISTRY_PASSWORD=" + secondSecret + "\n")},
					} {
						require.NoError(t, w.WriteHeader(&tar.Header{Name: file.name, Mode: 0600, Size: int64(len(file.content))}))
						_, err := w.Write(file.content)
						require.NoError(t, err)
					}
					require.NoError(t, w.Close())
					content, name = buf.Bytes(), "bundle.tar"
				}
				var found, after bool
				_, err := ProcessSingleFile(content, name, ProcessOptions{
					HitTimeout: time.Minute,
					ReportFinding: func(f scanner.Finding, file, ancestry string) {
						if strings.Contains(f.Text, "CI_REGISTRY_PASSWORD="+secret) {
							found = true
							assert.Equal(t, expectedFile, file)
							if container != "standalone" {
								assert.Equal(t, name, ancestry)
							}
						}
						if file == "after.env" && strings.Contains(f.Text, secondSecret) {
							after = true
						}
					},
				})
				require.NoError(t, err)
				assert.True(t, found, "expected the complete credential, including UTF-8 bytes")
				if container != "standalone" {
					assert.True(t, after, "a binary member must not prevent subsequent text members being scanned")
				}
			})
		}
	}
}

func TestDetermineFileTypeDoesNotTreatDocumentsAsArchives(t *testing.T) {
	for _, content := range [][]byte{
		append([]byte("\x7fELF"), make([]byte, 64)...),
		[]byte("MZ" + strings.Repeat("\x00", 70)),
		[]byte("\xfe\xed\xfa\xcf" + strings.Repeat("\x00", 70)),
		[]byte("%PDF-1.7\n"),
		[]byte("SQLite format 3\x00" + strings.Repeat("\x00", 70)),
	} {
		kind, err := filetype.Match(content)
		require.NoError(t, err)
		require.NotEqual(t, filetype.Unknown, kind)
		_, isArchive, _ := DetermineFileType(content)
		assert.False(t, isArchive, kind.Extension)
	}
}

func init() {
	scanner.InitRules([]string{})
}

func TestProcessZipArtifact(t *testing.T) {
	tests := []struct {
		name          string
		createZip     func() []byte
		opts          ProcessOptions
		expectError   bool
		expectResults int
	}{
		{
			name: "empty zip bytes",
			createZip: func() []byte {
				return []byte{}
			},
			opts:          ProcessOptions{MaxGoRoutines: 4},
			expectError:   false,
			expectResults: 0,
		},
		{
			name: "zip with text file",
			createZip: func() []byte {
				buf := new(bytes.Buffer)
				w := zip.NewWriter(buf)
				f, _ := w.Create("test.txt")
				_, _ = f.Write([]byte("test content"))
				_ = w.Close()
				return buf.Bytes()
			},
			opts:          ProcessOptions{MaxGoRoutines: 4, VerifyCredentials: false},
			expectError:   false,
			expectResults: 1,
		},
		{
			name: "zip with multiple files",
			createZip: func() []byte {
				buf := new(bytes.Buffer)
				w := zip.NewWriter(buf)
				f1, _ := w.Create("file1.txt")
				_, _ = f1.Write([]byte("content1"))
				f2, _ := w.Create("file2.txt")
				_, _ = f2.Write([]byte("content2"))
				f3, _ := w.Create("file3.txt")
				_, _ = f3.Write([]byte("content3"))
				_ = w.Close()
				return buf.Bytes()
			},
			opts:          ProcessOptions{MaxGoRoutines: 2, VerifyCredentials: false},
			expectError:   false,
			expectResults: 3,
		},
		{
			name: "invalid zip data",
			createZip: func() []byte {
				return []byte("not a zip file")
			},
			opts:        ProcessOptions{MaxGoRoutines: 4},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zipBytes := tt.createZip()
			results, err := ProcessZipArtifact(zipBytes, tt.opts)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, results, tt.expectResults)
			}
		})
	}
}

func TestExtractZipFile(t *testing.T) {
	tests := []struct {
		name          string
		createZipFile func() *zip.File
		expectContent string
		expectError   bool
	}{
		{
			name: "extract text file",
			createZipFile: func() *zip.File {
				buf := new(bytes.Buffer)
				w := zip.NewWriter(buf)
				f, _ := w.Create("test.txt")
				_, _ = f.Write([]byte("test content"))
				_ = w.Close()
				r, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
				return r.File[0]
			},
			expectContent: "test content",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zipFile := tt.createZipFile()
			content, err := ExtractZipFile(zipFile)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectContent, string(content))
			}
		})
	}
}

func TestDetermineFileType(t *testing.T) {
	tests := []struct {
		name            string
		content         []byte
		expectIsArchive bool
		expectIsUnknown bool
	}{
		{
			name:            "text file",
			content:         []byte("plain text content"),
			expectIsArchive: false,
			expectIsUnknown: true,
		},
		{
			name:            "json file",
			content:         []byte(`{"key": "value"}`),
			expectIsArchive: false,
			expectIsUnknown: true,
		},
		{
			name: "zip file",
			content: func() []byte {
				buf := new(bytes.Buffer)
				w := zip.NewWriter(buf)
				f, _ := w.Create("inner.txt")
				_, _ = f.Write([]byte("inner content"))
				_ = w.Close()
				return buf.Bytes()
			}(),
			expectIsArchive: true,
			expectIsUnknown: false,
		},
		{
			name:            "empty content",
			content:         []byte{},
			expectIsArchive: false,
			expectIsUnknown: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, isArchive, isUnknown := DetermineFileType(tt.content)
			assert.Equal(t, tt.expectIsArchive, isArchive)
			assert.Equal(t, tt.expectIsUnknown, isUnknown)
		})
	}
}

func TestProcessSingleFile(t *testing.T) {
	tests := []struct {
		name        string
		content     []byte
		filename    string
		opts        ProcessOptions
		expectError bool
	}{
		{
			name:     "text file",
			content:  []byte("plain text"),
			filename: "test.txt",
			opts: ProcessOptions{
				MaxGoRoutines:     4,
				VerifyCredentials: false,
				BuildURL:          "https://example.com/build/123",
				ArtifactName:      "test-artifact",
			},
			expectError: false,
		},
		{
			name:     "json file",
			content:  []byte(`{"key": "value"}`),
			filename: "config.json",
			opts: ProcessOptions{
				MaxGoRoutines:     4,
				VerifyCredentials: false,
			},
			expectError: false,
		},
		{
			name:     "empty file",
			content:  []byte{},
			filename: "empty.txt",
			opts: ProcessOptions{
				MaxGoRoutines: 4,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ProcessSingleFile(tt.content, tt.filename, tt.opts)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.filename, result.FileName)
				// FileType may be empty for unknown types, but the field should exist
				assert.NotNil(t, result)
			}
		})
	}
}

func TestProcessZipArtifact_WithContext(t *testing.T) {
	// Test that context-based parallel execution works correctly
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	// Create multiple files to test parallel processing
	for i := 0; i < 10; i++ {
		f, _ := w.Create("file" + string(rune('0'+i)) + ".txt")
		_, _ = f.Write([]byte("content " + string(rune('0'+i))))
	}
	_ = w.Close()

	opts := ProcessOptions{
		MaxGoRoutines:     2,
		VerifyCredentials: false,
		BuildURL:          "https://example.com/test",
		ArtifactName:      "multi-file-artifact",
	}

	results, err := ProcessZipArtifact(buf.Bytes(), opts)

	assert.NoError(t, err)
	assert.Len(t, results, 10)

	// Verify all files were processed
	for _, result := range results {
		assert.NoError(t, result.Error)
		assert.NotEmpty(t, result.FileName)
	}
}
