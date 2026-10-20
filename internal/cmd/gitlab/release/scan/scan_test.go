package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/testutil"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()
	testutil.AssertAllFlagsHaveBindings(t, cmd, flagBindings, "url", "token")
	assert.Equal(t, reflect.ValueOf(Scan).Pointer(), reflect.ValueOf(cmd.Run).Pointer())
	assert.Error(t, cmd.Args(cmd, []string{"extra"}))
	for name, value := range map[string]string{
		"release-limit": "0", "include-sources": "false", "max-artifact-size": "500Mb",
		"threads": "4", "hit-timeout": "1m0s", "secrets-verification": "true",
	} {
		require.NotNil(t, cmd.Flags().Lookup(name))
		assert.Equal(t, value, cmd.Flags().Lookup(name).DefValue, name)
	}
	assert.Nil(t, cmd.Flags().Lookup("artifacts"))
	assert.Nil(t, cmd.Flags().Lookup("cookie"))
}

func TestOptionsFromConfig(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_GITLAB_RELEASE_SCAN_TAG", "v2")
	t.Setenv("PIPELEEK_GITLAB_RELEASE_SCAN_REPO", "group/project")
	require.NoError(t, config.InitializeViper(""))
	parent := &cobra.Command{Use: "gl"}
	parent.PersistentFlags().String("url", "", "")
	parent.PersistentFlags().String("token", "", "")
	cmd := NewScanCmd()
	parent.AddCommand(cmd)
	require.NoError(t, cmd.ParseFlags([]string{"--url", "https://gitlab.example.com", "--token", "test-token", "--tag", "v3"}))
	require.NoError(t, config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind())
	config.GetViper().Set("common.hit_timeout", "120")
	opts, err := optionsFromConfig()
	require.NoError(t, err)
	assert.Equal(t, "v3", opts.Tag)
	assert.Equal(t, "group/project", opts.Repo)
	assert.Equal(t, 120*time.Second, opts.HitTimeout)
	assert.Equal(t, int64(500000000), opts.MaxBytes)
	config.GetViper().Set("common.max_artifact_size", "bad")
	_, err = optionsFromConfig()
	require.Error(t, err)
	config.GetViper().Set("common.max_artifact_size", "1Mb")
	config.GetViper().Set("common.hit_timeout", "bad")
	_, err = optionsFromConfig()
	require.ErrorContains(t, err, "hit-timeout")
}

func TestConfigurationPrecedence(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "")
	file := filepath.Join(t.TempDir(), "pipeleek.yaml")
	require.NoError(t, os.WriteFile(file, []byte(`gitlab:
  url: https://gitlab.example.com
  token: test-token
  release:
    scan:
      repo: group/project
      release_limit: 7
      include_sources: true
common:
  threads: 3
`), 0600))
	t.Setenv("PIPELEEK_GITLAB_RELEASE_SCAN_RELEASE_LIMIT", "5")
	require.NoError(t, config.InitializeViper(file))
	cmd := NewScanCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--release-limit", "2"}))
	require.NoError(t, config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind())
	opts, err := optionsFromConfig()
	require.NoError(t, err)
	assert.Equal(t, 2, opts.ReleaseLimit)
	assert.Equal(t, 3, opts.Threads)
	assert.True(t, opts.IncludeSources)
	assert.Equal(t, "group/project", opts.Repo)
	require.NoError(t, config.InitializeViper(file))
	cmd = NewScanCmd()
	require.NoError(t, config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind())
	opts, err = optionsFromConfig()
	require.NoError(t, err)
	assert.Equal(t, 5, opts.ReleaseLimit)
}
