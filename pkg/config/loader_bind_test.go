package config

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetViper resets the global viper instance for tests.
func resetViper(t *testing.T) {
	t.Helper()
	globalViper = nil
	if err := InitializeViper(""); err != nil {
		t.Fatalf("failed to init viper: %v", err)
	}
}

func TestCommandSetupBind_LocalFlags(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("my-flag", "default", "")

	if err := NewCommandSetup(cmd).WithFlagBindings(map[string]string{"my-flag": "gitlab.scan.my_flag"}).Bind(); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := cmd.Flags().Set("my-flag", "cli-value"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if got := GetViper().GetString("gitlab.scan.my_flag"); got != "cli-value" {
		t.Fatalf("expected cli-value, got %q", got)
	}
}

func TestCommandSetupBind_Overrides(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("url", "https://example.com", "")

	if err := NewCommandSetup(cmd).WithFlagBindings(map[string]string{"url": "gitlab.url"}).Bind(); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := cmd.Flags().Set("url", "https://override.example.com"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if got := GetViper().GetString("gitlab.url"); got != "https://override.example.com" {
		t.Fatalf("expected override value, got %q", got)
	}
}

func TestCommandSetupBind_InheritedFlags(t *testing.T) {
	resetViper(t)

	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("token", "", "")

	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	if err := NewCommandSetup(child).WithFlagBindings(map[string]string{"token": "gitlab.token"}).Bind(); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := root.PersistentFlags().Set("token", "from-root"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if got := GetViper().GetString("gitlab.token"); got != "from-root" {
		t.Fatalf("expected inherited flag value, got %q", got)
	}
}

func TestCommandSetupBind_LocalFlag(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("token", "", "API token")

	err := NewCommandSetup(cmd).WithFlagBindings(map[string]string{"token": "gitlab.token"}).Bind()
	require.NoError(t, err)

	require.NoError(t, cmd.Flags().Set("token", "my-token"))
	assert.Equal(t, "my-token", GetString("gitlab.token"))
}

func TestCommandSetupBind_InheritedFlag(t *testing.T) {
	resetViper(t)

	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("url", "", "GitLab URL")

	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	err := NewCommandSetup(child).WithFlagBindings(map[string]string{"url": "gitlab.url"}).Bind()
	require.NoError(t, err)

	require.NoError(t, root.PersistentFlags().Set("url", "https://gitlab.example.com"))
	assert.Equal(t, "https://gitlab.example.com", GetString("gitlab.url"))
}

func TestCommandSetupBind_UnknownFlagIsIgnored(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}

	// A flag that doesn't exist should be silently ignored, not error
	err := NewCommandSetup(cmd).WithFlagBindings(map[string]string{"nonexistent-flag": "some.key"}).Bind()
	assert.NoError(t, err)
}

func TestCommandSetupBind_MultipleFlags(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("token", "", "API token")
	cmd.Flags().String("url", "", "URL")
	cmd.Flags().Int("threads", 4, "Thread count")

	err := NewCommandSetup(cmd).WithFlagBindings(map[string]string{
		"token":   "gitlab.token",
		"url":     "gitlab.url",
		"threads": "common.threads",
	}).Bind()
	require.NoError(t, err)

	require.NoError(t, cmd.Flags().Set("token", "abc123"))
	require.NoError(t, cmd.Flags().Set("url", "https://gitlab.com"))
	require.NoError(t, cmd.Flags().Set("threads", "8"))

	assert.Equal(t, "abc123", GetString("gitlab.token"))
	assert.Equal(t, "https://gitlab.com", GetString("gitlab.url"))
	assert.Equal(t, 8, GetInt("common.threads"))
}

func TestUnmarshalConfig_Defaults(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)
	t.Setenv("PIPELEEK_NO_CONFIG", "")

	resetViper(t)

	cfg, err := UnmarshalConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify default values are populated
	assert.Equal(t, 4, cfg.Common.Threads)
	assert.True(t, cfg.Common.TruffleHogVerification)
	assert.Equal(t, "500Mb", cfg.Common.MaxArtifactSize)
	assert.Equal(t, "https://api.github.com", cfg.GitHub.URL)
	assert.Equal(t, "https://api.bitbucket.org/2.0", cfg.BitBucket.URL)
	assert.Equal(t, "https://dev.azure.com", cfg.AzureDevOps.URL)
}

func TestUnmarshalConfig_WithSetValues(t *testing.T) {
	resetViper(t)

	v := GetViper()
	v.Set("gitlab.url", "https://mygitlab.com")
	v.Set("gitlab.token", "glpat-secret")
	v.Set("common.threads", 16)

	cfg, err := UnmarshalConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "https://mygitlab.com", cfg.GitLab.URL)
	assert.Equal(t, "glpat-secret", cfg.GitLab.Token)
	assert.Equal(t, 16, cfg.Common.Threads)
}
