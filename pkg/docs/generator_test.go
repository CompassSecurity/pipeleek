package docs

import (
	"os"
	"path/filepath"
	"runtime"
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

// TestGenerateDocs_LeafCommand verifies that a leaf command creates a .md file.
func TestGenerateDocs_LeafCommand(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan for secrets",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	err := generateDocs(cmd, tmpDir, 1, false)
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(tmpDir, "scan.md"))
	assert.NoError(t, err, "leaf command should create a .md file")
}

// TestGenerateDocs_ParentCommand verifies that a parent command creates index.md in a subdirectory.
func TestGenerateDocs_ParentCommand(t *testing.T) {
	tmpDir := t.TempDir()

	parent := &cobra.Command{Use: "gitlab", Short: "GitLab commands"}
	child := &cobra.Command{
		Use:   "scan",
		Short: "Scan CI/CD",
		Run:   func(cmd *cobra.Command, args []string) {},
	}
	parent.AddCommand(child)

	err := generateDocs(parent, tmpDir, 0, false)
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(tmpDir, "gitlab", "index.md"))
	assert.NoError(t, err, "parent command should create index.md in subdirectory")

	_, err = os.Stat(filepath.Join(tmpDir, "gitlab", "scan.md"))
	assert.NoError(t, err, "child command should create scan.md")
}

// TestGenerateDocs_GithubPages verifies link rewriting for GitHub Pages.
func TestGenerateDocs_GithubPages(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan for secrets",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	err := generateDocs(cmd, tmpDir, 1, true)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(tmpDir, "scan.md"))
	require.NoError(t, err)
	assert.NotEmpty(t, content, "generated docs should not be empty")
}

// TestGenerateDocs_OutputDirNotWritable verifies that an error is returned when the dir is not writable.
func TestGenerateDocs_OutputDirNotWritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping: running as root, permission restrictions don't apply")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping: read-only directory restriction test is Unix-specific")
	}
	tmpDir := t.TempDir()
	// Create a read-only subdirectory so MkdirAll will fail for children
	readonlyDir := filepath.Join(tmpDir, "readonly")
	require.NoError(t, os.MkdirAll(readonlyDir, 0500))

	parent := &cobra.Command{Use: "sub", Short: "sub with children"}
	child := &cobra.Command{
		Use:   "leaf",
		Short: "leaf cmd",
		Run:   func(cmd *cobra.Command, args []string) {},
	}
	parent.AddCommand(child)

	// generateDocs for a parent creates subdirectory - this should fail in the read-only dir
	err := generateDocs(parent, readonlyDir, 0, false)
	assert.Error(t, err, "should return error when output dir is not writable")
}

// TestInlineSVGIntoGettingStarted_MissingFile verifies an error is returned when the markdown is missing.
func TestInlineSVGIntoGettingStarted_MissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	err := inlineSVGIntoGettingStarted(tmpDir)
	assert.Error(t, err, "should return error when getting_started.md does not exist")
}

// TestInlineSVGIntoGettingStarted_NoPlaceholder verifies early return when placeholder is absent.
func TestInlineSVGIntoGettingStarted_NoPlaceholder(t *testing.T) {
	tmpDir := t.TempDir()

	introDir := filepath.Join(tmpDir, "introduction")
	require.NoError(t, os.MkdirAll(introDir, 0755))
	mdPath := filepath.Join(introDir, "getting_started.md")
	require.NoError(t, os.WriteFile(mdPath, []byte("# Getting Started\nNo placeholder here."), 0644))

	err := inlineSVGIntoGettingStarted(tmpDir)
	assert.NoError(t, err, "no placeholder should return nil without error")

	// File should be unchanged
	content, err := os.ReadFile(mdPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "No placeholder here.")
}

// TestInlineSVGIntoGettingStarted_MissingSVG verifies an error is returned when the SVG file is missing.
func TestInlineSVGIntoGettingStarted_MissingSVG(t *testing.T) {
	tmpDir := t.TempDir()

	introDir := filepath.Join(tmpDir, "introduction")
	require.NoError(t, os.MkdirAll(introDir, 0755))
	mdPath := filepath.Join(introDir, "getting_started.md")
	placeholder := "<!-- INLINE_SVG:pipeleek-anim.svg -->"
	require.NoError(t, os.WriteFile(mdPath, []byte("# Getting Started\n"+placeholder), 0644))

	// Change to tmpDir so the SVG file path ("docs/pipeleek-anim.svg") is relative to it
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(tmpDir))
	defer func() { _ = os.Chdir(origDir) }()

	err := inlineSVGIntoGettingStarted(tmpDir)
	assert.Error(t, err, "should return error when SVG file does not exist")
}

// TestInlineSVGIntoGettingStarted_ReplacesPlaceholder verifies SVG content is inlined.
func TestInlineSVGIntoGettingStarted_ReplacesPlaceholder(t *testing.T) {
	tmpDir := t.TempDir()

	introDir := filepath.Join(tmpDir, "introduction")
	require.NoError(t, os.MkdirAll(introDir, 0755))
	placeholder := "<!-- INLINE_SVG:pipeleek-anim.svg -->"
	mdContent := "# Getting Started\n" + placeholder + "\nEnd of file."
	mdPath := filepath.Join(introDir, "getting_started.md")
	require.NoError(t, os.WriteFile(mdPath, []byte(mdContent), 0644))

	// Create a mock SVG at the expected relative path "docs/pipeleek-anim.svg"
	docsDir := filepath.Join(tmpDir, "docs")
	require.NoError(t, os.MkdirAll(docsDir, 0755))
	svgContent := `<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>`
	require.NoError(t, os.WriteFile(filepath.Join(docsDir, "pipeleek-anim.svg"), []byte(svgContent), 0644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(tmpDir))
	defer func() { _ = os.Chdir(origDir) }()

	err := inlineSVGIntoGettingStarted(tmpDir)
	require.NoError(t, err)

	result, err := os.ReadFile(mdPath)
	require.NoError(t, err)
	assert.Contains(t, string(result), svgContent, "SVG content should be inlined")
	assert.NotContains(t, string(result), placeholder, "placeholder should be replaced")
}
