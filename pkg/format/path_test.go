package format

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsDirectory(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "testfile.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	testDir := filepath.Join(tmpDir, "testdir")
	if err := os.Mkdir(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "existing directory",
			path:     testDir,
			expected: true,
		},
		{
			name:     "existing file",
			path:     testFile,
			expected: false,
		},
		{
			name:     "non-existent path",
			path:     filepath.Join(tmpDir, "nonexistent"),
			expected: true,
		},
		{
			name:     "empty path",
			path:     "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsDirectory(tt.path)
			if result != tt.expected {
				t.Errorf("IsDirectory(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}
