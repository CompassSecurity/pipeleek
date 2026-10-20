package gen_test

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/release"
	"github.com/CompassSecurity/pipeleek/pkg/config/gen"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestReleaseScanConfig(t *testing.T) {
	root := &cobra.Command{Use: "pipeleek"}
	gl := &cobra.Command{Use: "gl"}
	gl.PersistentFlags().String("url", "", "")
	gl.PersistentFlags().String("token", "", "")
	gl.AddCommand(release.NewReleaseRootCmd())
	root.AddCommand(gl)
	for _, name := range []string{"repo", "namespace", "search", "owned", "member", "tag", "release_limit", "include_sources"} {
		assert.True(t, gen.IsAllowedConfigPath(root, "gitlab.release.scan."+name), name)
	}
	for _, name := range []string{"threads", "max_artifact_size", "hit_timeout", "webui", "secrets_verification"} {
		assert.True(t, gen.IsAllowedConfigPath(root, "common."+name), name)
	}
	content := gen.GenerateExampleConfig(root)
	var parsed struct {
		GitLab struct {
			Release struct {
				Scan struct {
					ReleaseLimit   int  `yaml:"release_limit"`
					IncludeSources bool `yaml:"include_sources"`
				}
			}
		}
	}
	require.NoError(t, yaml.Unmarshal([]byte(content), &parsed))
	assert.Zero(t, parsed.GitLab.Release.Scan.ReleaseLimit)
	assert.False(t, parsed.GitLab.Release.Scan.IncludeSources)
	assert.Contains(t, content, "PIPELEEK_GITLAB_RELEASE_SCAN_RELEASE_LIMIT")
}
