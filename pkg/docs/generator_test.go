package docs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Test getFileName logic for level handling and GroupID usage.
func TestGetFileName(t *testing.T) {
	cmdNoGroup := &cobra.Command{Use: "scan", Short: "scan"}
	cmdGroup := &cobra.Command{Use: "enum", GroupID: "enumeration"}

	assert.Equal(t, "scan.md", getFileName(cmdNoGroup, 1))
	assert.Equal(t, "enumeration.md", getFileName(cmdGroup, 1))
	assert.Equal(t, "scan.md", getFileName(cmdNoGroup, 2)) // level >1 ignores GroupID logic
}

// Test displayName title casing and GroupID preference.
func TestDisplayName(t *testing.T) {
	cmdNoGroup := &cobra.Command{Use: "list"}
	cmdGroup := &cobra.Command{Use: "enum", GroupID: "gitlab pentest"}

	assert.Equal(t, "List", displayName(cmdNoGroup, 1))
	assert.Equal(t, "Gitlab Pentest", displayName(cmdGroup, 1)) // Title case applied
	assert.Equal(t, "Enum", displayName(cmdGroup, 2))           // deeper level uses Name
}

// buildNav should create index.md for commands with children and .md file for leaves.
// It should also filter out 'completion' and 'docs' commands.
func TestBuildNav(t *testing.T) {
	root := &cobra.Command{Use: "pipeleek"}
	parent := &cobra.Command{Use: "alpha"}
	leaf := &cobra.Command{Use: "scan", Run: func(cmd *cobra.Command, args []string) {}}
	completion := &cobra.Command{Use: "completion", Run: func(cmd *cobra.Command, args []string) {}}
	docs := &cobra.Command{Use: "docs", Run: func(cmd *cobra.Command, args []string) {}}
	parent.AddCommand(leaf)
	parent.AddCommand(completion)
	parent.AddCommand(docs)
	root.AddCommand(parent)

	entry := buildNav(root, 0, "")
	assert.Equal(t, "Pipeleek", entry.Label)
	assert.Len(t, entry.Children, 1)
	child := entry.Children[0]
	assert.Equal(t, "Alpha", child.Label)
	assert.Equal(t, filepath.ToSlash("pipeleek/alpha/index.md"), child.FilePath)
	// Should only have 1 child (scan), completion and docs should be filtered
	assert.Len(t, child.Children, 1)
	grand := child.Children[0]
	assert.Equal(t, "Scan", grand.Label)
	assert.Equal(t, filepath.ToSlash("pipeleek/alpha/scan.md"), grand.FilePath)
}

// convertNavToYaml should trim pipeleek/ prefix and .md suffix.
func TestConvertNavToYaml(t *testing.T) {
	entries := []*NavEntry{
		{Label: "Alpha", FilePath: filepath.ToSlash("pipeleek/alpha/index.md"), Children: []*NavEntry{}},
		{Label: "Beta", FilePath: filepath.ToSlash("pipeleek/beta/leaf.md"), Children: []*NavEntry{}},
	}
	yamlList := convertNavToYaml(entries)
	// Entries become maps with label key
	assert.Len(t, yamlList, 2)
	// Validate trimming and removal of extension
	alphaMap := yamlList[0]
	betaMap := yamlList[1]
	assert.Equal(t, "alpha/index", alphaMap["Alpha"])
	assert.Equal(t, "beta/leaf", betaMap["Beta"])
}

// writeMkdocsYaml should create mkdocs.yml with expected keys and nav entries.
func TestWriteMkdocsYaml(t *testing.T) {
	root := &cobra.Command{Use: "pipeleek"}
	alpha := &cobra.Command{Use: "alpha", Run: func(cmd *cobra.Command, args []string) {}}
	deepParent := &cobra.Command{Use: "beta"}
	deepChild := &cobra.Command{Use: "deep", Run: func(cmd *cobra.Command, args []string) {}}
	deepParent.AddCommand(deepChild)
	root.AddCommand(alpha)
	root.AddCommand(deepParent)

	tmpDir := t.TempDir()
	// Change working directory to module root so relative docs path resolves correctly
	wd, _ := os.Getwd()
	// From pkg/docs go up two levels to repo root
	rootDir := filepath.Clean(filepath.Join(wd, "..", ".."))
	old := wd
	if err := os.Chdir(rootDir); err != nil {
		t.Fatalf("failed to chdir to root: %v", err)
	}
	defer func() { _ = os.Chdir(old) }()

	err := writeMkdocsYaml(root, tmpDir, false)
	assert.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(tmpDir, "mkdocs.yml"))
	assert.NoError(t, err)

	var parsed map[string]interface{}
	err = yaml.Unmarshal(data, &parsed)
	assert.NoError(t, err)

	// Basic keys exist
	assert.Equal(t, "Pipeleek", parsed["site_name"])
	assert.Equal(t, "pipeleek", parsed["docs_dir"])

	// Nav structure assertions
	navAny, ok := parsed["nav"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 4, len(navAny)) // intro, guides, alpha, beta

	// Introduction entry first (now a list of sub-items)
	introMap, ok := navAny[0].(map[string]interface{})
	assert.True(t, ok)
	assert.Contains(t, introMap, "Introduction")
	introItems, ok := introMap["Introduction"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 5, len(introItems)) // Getting Started, Configuration, Logging, Secrets Verification, Proxying

	// Guides second (was Methodology)
	guidesMap, ok := navAny[1].(map[string]interface{})
	assert.True(t, ok)
	assert.Contains(t, guidesMap, "Guides")

	// Command entries appear after guides
	foundAlpha := false
	foundBeta := false
	for _, item := range navAny[2:] {
		if m, ok := item.(map[string]interface{}); ok {
			if _, ok := m["Alpha"]; ok {
				foundAlpha = true
			}
			if _, ok := m["Beta"]; ok {
				foundBeta = true
			}
		}
	}
	assert.True(t, foundAlpha)
	assert.True(t, foundBeta)
}

// writeMkdocsYaml with GithubPages should prefix nav paths.
func TestWriteMkdocsYaml_GithubPagesPrefix(t *testing.T) {
	root := &cobra.Command{Use: "pipeleek"}
	root.AddCommand(&cobra.Command{Use: "alpha", Run: func(cmd *cobra.Command, args []string) {}})

	tmpDir := t.TempDir()
	wd, _ := os.Getwd()
	rootDir := filepath.Clean(filepath.Join(wd, "..", ".."))
	old := wd
	if err := os.Chdir(rootDir); err != nil {
		t.Fatalf("failed to chdir to root: %v", err)
	}
	defer func() { _ = os.Chdir(old) }()

	err := writeMkdocsYaml(root, tmpDir, true)
	assert.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(tmpDir, "mkdocs.yml"))
	assert.NoError(t, err)
	var parsed map[string]interface{}
	err = yaml.Unmarshal(data, &parsed)
	assert.NoError(t, err)
	navAny := parsed["nav"].([]interface{})
	introMap := navAny[0].(map[string]interface{})
	// Introduction is now a list of sub-items with prefixed paths
	introItems, ok := introMap["Introduction"].([]interface{})
	assert.True(t, ok)
	assert.GreaterOrEqual(t, len(introItems), 1)
	// First item should be Getting Started with GitHub Pages prefix
	firstItem := introItems[0].(map[string]interface{})
	assert.Equal(t, "/pipeleek/introduction/getting_started/", firstItem["Getting Started"])
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()

	srcPath := filepath.Join(tmpDir, "source.txt")
	dstPath := filepath.Join(tmpDir, "dest.txt")

	content := []byte("hello, test content")
	require.NoError(t, os.WriteFile(srcPath, content, 0644))

	err := copyFile(srcPath, dstPath)
	assert.NoError(t, err)

	got, err := os.ReadFile(dstPath)
	assert.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestCopyFile_SourceNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	err := copyFile(filepath.Join(tmpDir, "nonexistent.txt"), filepath.Join(tmpDir, "dst.txt"))
	assert.Error(t, err)
}

func TestCopyFile_DestinationNotWritable(t *testing.T) {
	tmpDir := t.TempDir()

	srcPath := filepath.Join(tmpDir, "source.txt")
	require.NoError(t, os.WriteFile(srcPath, []byte("data"), 0644))

	// Try to write to a directory path (should fail)
	err := copyFile(srcPath, tmpDir)
	assert.Error(t, err)
}

func TestCopyDir(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create files in source
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("aaa"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("bbb"), 0644))

	// Create a subdirectory
	subDir := filepath.Join(srcDir, "sub")
	require.NoError(t, os.Mkdir(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "c.txt"), []byte("ccc"), 0644))

	err := copyDir(srcDir, dstDir)
	assert.NoError(t, err)

	// Verify files were copied
	gotA, err := os.ReadFile(filepath.Join(dstDir, "a.txt"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("aaa"), gotA)

	gotB, err := os.ReadFile(filepath.Join(dstDir, "b.txt"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("bbb"), gotB)

	gotC, err := os.ReadFile(filepath.Join(dstDir, "sub", "c.txt"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("ccc"), gotC)
}

func TestCopyDir_SourceNotExist(t *testing.T) {
	dstDir := t.TempDir()
	err := copyDir("/nonexistent/path", dstDir)
	assert.Error(t, err)
}

func TestCopySubfolders(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create subdirectories with files in source (only subdirs should be copied, not root files)
	sub1 := filepath.Join(srcDir, "sub1")
	sub2 := filepath.Join(srcDir, "sub2")
	require.NoError(t, os.Mkdir(sub1, 0755))
	require.NoError(t, os.Mkdir(sub2, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sub1, "file1.txt"), []byte("f1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sub2, "file2.txt"), []byte("f2"), 0644))

	// Root-level file (should NOT be copied by copySubfolders)
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "root.txt"), []byte("root"), 0644))

	err := copySubfolders(srcDir, dstDir)
	assert.NoError(t, err)

	// Subdirectory files should be present
	got1, err := os.ReadFile(filepath.Join(dstDir, "sub1", "file1.txt"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("f1"), got1)

	got2, err := os.ReadFile(filepath.Join(dstDir, "sub2", "file2.txt"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("f2"), got2)

	// Root-level file should NOT be copied
	_, err = os.Stat(filepath.Join(dstDir, "root.txt"))
	assert.True(t, os.IsNotExist(err), "root-level files should not be copied by copySubfolders")
}

func TestCopySubfolders_SourceNotExist(t *testing.T) {
	dstDir := t.TempDir()
	err := copySubfolders("/nonexistent/path", dstDir)
	assert.Error(t, err)
}
