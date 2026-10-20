package docs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/release"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReleaseScanDocumentation(t *testing.T) {
	root := &cobra.Command{Use: "pipeleek"}
	gl := &cobra.Command{Use: "gl"}
	gl.AddCommand(release.NewReleaseRootCmd())
	root.AddCommand(gl)
	output := t.TempDir()
	require.NoError(t, generateDocs(root, output, 0, false))
	data, err := os.ReadFile(filepath.Join(output, "pipeleek", "gl", "release", "scan.md"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "pipeleek gl release scan")
	assert.Contains(t, string(data), "--include-sources")
	assert.Contains(t, string(data), "--release-limit")
	nav := buildNav(root, 0, "")
	require.Len(t, nav.Children, 1)
	require.Len(t, nav.Children[0].Children, 1)
	releaseNav := nav.Children[0].Children[0]
	assert.Equal(t, "Release", releaseNav.Label)
	require.Len(t, releaseNav.Children, 1)
	assert.Equal(t, "pipeleek/gl/release/scan.md", releaseNav.Children[0].FilePath)
}
