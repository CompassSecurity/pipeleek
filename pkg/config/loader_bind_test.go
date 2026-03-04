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

func TestBindCommandFlags_LocalFlags(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("my-flag", "default", "")

	if err := BindCommandFlags(cmd, "gitlab.scan", nil); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := cmd.Flags().Set("my-flag", "cli-value"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if got := GetViper().GetString("gitlab.scan.my_flag"); got != "cli-value" {
		t.Fatalf("expected cli-value, got %q", got)
	}
}

func TestBindCommandFlags_Overrides(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("gitlab", "https://example.com", "")

	if err := BindCommandFlags(cmd, "gitlab.scan", map[string]string{"gitlab": "gitlab.url"}); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := cmd.Flags().Set("gitlab", "https://override.example.com"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if got := GetViper().GetString("gitlab.url"); got != "https://override.example.com" {
		t.Fatalf("expected override value, got %q", got)
	}
}

func TestBindCommandFlags_InheritedFlags(t *testing.T) {
	resetViper(t)

	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("token", "", "")

	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	if err := BindCommandFlags(child, "gitlab.enum", map[string]string{"token": "gitlab.token"}); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := root.PersistentFlags().Set("token", "from-root"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if got := GetViper().GetString("gitlab.token"); got != "from-root" {
		t.Fatalf("expected inherited flag value, got %q", got)
	}
}

func TestAutoBindFlags_LocalFlag(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("token", "", "API token")

	err := AutoBindFlags(cmd, map[string]string{"token": "gitlab.token"})
	require.NoError(t, err)

	require.NoError(t, cmd.Flags().Set("token", "my-token"))
	assert.Equal(t, "my-token", GetString("gitlab.token"))
}

func TestAutoBindFlags_InheritedFlag(t *testing.T) {
	resetViper(t)

	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("url", "", "GitLab URL")

	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	err := AutoBindFlags(child, map[string]string{"url": "gitlab.url"})
	require.NoError(t, err)

	require.NoError(t, root.PersistentFlags().Set("url", "https://gitlab.example.com"))
	assert.Equal(t, "https://gitlab.example.com", GetString("gitlab.url"))
}

func TestAutoBindFlags_UnknownFlagIsIgnored(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}

	// A flag that doesn't exist should be silently ignored, not error
	err := AutoBindFlags(cmd, map[string]string{"nonexistent-flag": "some.key"})
	assert.NoError(t, err)
}

func TestAutoBindFlags_MultipleFlags(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("token", "", "API token")
	cmd.Flags().String("url", "", "URL")
	cmd.Flags().Int("threads", 4, "Thread count")

	err := AutoBindFlags(cmd, map[string]string{
		"token":   "gitlab.token",
		"url":     "gitlab.url",
		"threads": "common.threads",
	})
	require.NoError(t, err)

	require.NoError(t, cmd.Flags().Set("token", "abc123"))
	require.NoError(t, cmd.Flags().Set("url", "https://gitlab.com"))
	require.NoError(t, cmd.Flags().Set("threads", "8"))

	assert.Equal(t, "abc123", GetString("gitlab.token"))
	assert.Equal(t, "https://gitlab.com", GetString("gitlab.url"))
	assert.Equal(t, 8, GetInt("common.threads"))
}

func TestUnmarshalConfig_Defaults(t *testing.T) {
	resetViper(t)

	cfg, err := UnmarshalConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify default values are populated
	assert.Equal(t, 4, cfg.Common.Threads)
	assert.True(t, cfg.Common.TruffleHogVerification)
	assert.Equal(t, "500Mb", cfg.Common.MaxArtifactSize)
	assert.Equal(t, "https://api.github.com", cfg.GitHub.URL)
	assert.Equal(t, "https://bitbucket.org", cfg.BitBucket.URL)
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
