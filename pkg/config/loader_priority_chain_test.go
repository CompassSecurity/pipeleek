package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigPriorityChain_FlagOverridesAll verifies that CLI flags have highest priority
// and override env vars, config file, and defaults.
func TestConfigPriorityChain_FlagOverridesAll(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a config file with specific values
	configContent := `
common:
  threads: 2
  max_artifact_size: "100Mb"
gitlab:
  url: https://gitlab-file.com
  token: file-token
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variables
	t.Setenv("PIPELEEK_COMMON_THREADS", "3")
	t.Setenv("PIPELEEK_GITLAB_URL", "https://gitlab-env.com")
	t.Setenv("PIPELEEK_GITLAB_TOKEN", "env-token")

	// Initialize Viper with config file
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Create command and set CLI flags
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("token", "", "GitLab token")
	cmd.Flags().Int("threads", 0, "Thread count")

	cmd.Flags().String("url", "", "GitLab URL")

	err = cmd.Flags().Set("url", "https://gitlab-flag.com")
	require.NoError(t, err)
	err = cmd.Flags().Set("token", "flag-token")
	require.NoError(t, err)
	err = cmd.Flags().Set("threads", "5")
	require.NoError(t, err)

	// Bind CLI flags to config keys
	err = AutoBindFlags(cmd, map[string]string{
		"url":     "gitlab.url",
		"token":   "gitlab.token",
		"threads": "common.threads",
	})
	require.NoError(t, err)

	// Verify CLI flags win over env vars, config file, and defaults
	assert.Equal(t, "https://gitlab-flag.com", GetString("gitlab.url"), "CLI flag should override env var, config file, and default")
	assert.Equal(t, "flag-token", GetString("gitlab.token"), "CLI flag should override env var, config file, and default")
	assert.Equal(t, 5, GetInt("common.threads"), "CLI flag should override env var, config file, and default")
}

// TestConfigPriorityChain_EnvVarOverridesFileAndDefault verifies that environment variables
// have second priority and override config file and defaults (when no CLI flag is set).
func TestConfigPriorityChain_EnvVarOverridesFileAndDefault(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a config file with specific values
	configContent := `
common:
  threads: 2
gitlab:
  url: https://gitlab-file.com
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variables (no CLI flags)
	t.Setenv("PIPELEEK_COMMON_THREADS", "3")
	t.Setenv("PIPELEEK_GITLAB_URL", "https://gitlab-env.com")

	// Initialize Viper with config file
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Create command WITHOUT setting CLI flags
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("url", "", "GitLab URL")
	cmd.Flags().Int("threads", 0, "Thread count")

	// Bind (but don't set) CLI flags
	err = AutoBindFlags(cmd, map[string]string{
		"url":     "gitlab.url",
		"threads": "common.threads",
	})
	require.NoError(t, err)

	// Verify env vars override config file
	assert.Equal(t, "https://gitlab-env.com", GetString("gitlab.url"), "Env var should override config file")
	assert.Equal(t, 3, GetInt("common.threads"), "Env var should override config file")
}

// TestConfigPriorityChain_ConfigFileOverridesDefault verifies that config file values
// override defaults (when no CLI flag or env var is set).
func TestConfigPriorityChain_ConfigFileOverridesDefault(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a config file with specific values
	configContent := `
common:
  threads: 2
  max_artifact_size: "100Mb"
gitlab:
  url: https://gitlab-file.com
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// NO environment variables set, NO CLI flags set
	t.Setenv("PIPELEEK_NO_CONFIG", "") // Allow config file to be loaded

	// Initialize Viper with config file
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Create command WITHOUT setting CLI flags or env vars
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("url", "", "GitLab URL")
	cmd.Flags().Int("threads", 0, "Thread count")

	// Bind (but don't set) CLI flags
	err = AutoBindFlags(cmd, map[string]string{
		"url":     "gitlab.url",
		"threads": "common.threads",
	})
	require.NoError(t, err)

	// Verify config file values are used
	assert.Equal(t, "https://gitlab-file.com", GetString("gitlab.url"), "Config file should override default")
	assert.Equal(t, 2, GetInt("common.threads"), "Config file should override default")
	assert.Equal(t, "100Mb", GetString("common.max_artifact_size"), "Config file should override default")
}

// TestConfigPriorityChain_PartialOverrides verifies selective override behavior
// where flag overrides file for one key, env var overrides default for another.
func TestConfigPriorityChain_PartialOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a config file with specific values
	configContent := `
common:
  threads: 2
  hit_timeout: "120s"
gitlab:
  url: https://gitlab-file.com
  token: file-token
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set only SOME environment variables
	t.Setenv("PIPELEEK_COMMON_THREADS", "3")
	// Note: NOT setting PIPELEEK_GITLAB_TOKEN

	// Initialize Viper with config file
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Create command and set ONLY SOME CLI flags
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("url", "", "GitLab URL")
	cmd.Flags().String("token", "", "GitLab token")
	cmd.Flags().Int("threads", 0, "Thread count")

	// Set flag only for one value
	err = cmd.Flags().Set("url", "https://gitlab-flag.com")
	require.NoError(t, err)
	// Note: NOT setting token or threads flags

	// Bind all flags
	err = AutoBindFlags(cmd, map[string]string{
		"url":     "gitlab.url",
		"token":   "gitlab.token",
		"threads": "common.threads",
	})
	require.NoError(t, err)

	// Verify selective override behavior
	assert.Equal(t, "https://gitlab-flag.com", GetString("gitlab.url"), "CLI flag should override config file")
	assert.Equal(t, "file-token", GetString("gitlab.token"), "Config file should be used when no flag or env var")
	assert.Equal(t, 3, GetInt("common.threads"), "Env var should override config file")
}

// TestConfigPriorityChain_AllLevelsSet verifies the complete precedence when
// ALL levels (flag, env, file, default) are set for the same key.
func TestConfigPriorityChain_AllLevelsSet(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a config file
	configContent := `
common:
  threads: 2
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variable
	t.Setenv("PIPELEEK_COMMON_THREADS", "3")

	// Initialize Viper with config file
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Set CLI flag
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Int("threads", 1, "Thread count (default=1)")

	err = cmd.Flags().Set("threads", "5")
	require.NoError(t, err)

	// Bind CLI flag
	err = AutoBindFlags(cmd, map[string]string{
		"threads": "common.threads",
	})
	require.NoError(t, err)

	// Verify precedence: flag (5) > env var (3) > config file (2) > default (1)
	threads := GetInt("common.threads")
	assert.Equal(t, 5, threads, "CLI flag has highest priority (5 > 3 > 2 > 1)")
}

// TestConfigPriorityChain_EmptyFlagDoesNotOverride verifies that an empty/unset
// CLI flag does not override lower-priority sources.
func TestConfigPriorityChain_EmptyFlagDoesNotOverride(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a config file
	configContent := `
gitlab:
  token: file-token
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Initialize Viper with config file
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Create command with flag but don't set it (should remain empty default)
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("token", "", "Token (empty default)")

	// Bind flag
	err = AutoBindFlags(cmd, map[string]string{
		"token": "gitlab.token",
	})
	require.NoError(t, err)

	// Verify empty flag does NOT override config file value
	token := GetString("gitlab.token")
	assert.Equal(t, "file-token", token, "Empty flag should not override config file value")
}

// TestConfigPriorityChain_MultipleKeysIndependent verifies that priority order
// is applied independently per key (one key's value doesn't affect another's).
func TestConfigPriorityChain_MultipleKeysIndependent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
gitlab:
  url: https://gitlab-file.com
  token: file-token
  email: file@example.com
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set env vars for some keys
	t.Setenv("PIPELEEK_GITLAB_URL", "https://gitlab-env.com")
	// Note: NOT setting PIPELEEK_GITLAB_TOKEN or PIPELEEK_GITLAB_EMAIL

	// Initialize Viper
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Set CLI flags for one key
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("url", "", "GitLab URL")
	cmd.Flags().String("token", "", "GitLab token")
	cmd.Flags().String("email", "", "GitLab email")

	err = cmd.Flags().Set("token", "flag-token")
	require.NoError(t, err)

	err = AutoBindFlags(cmd, map[string]string{
		"url":   "gitlab.url",
		"token": "gitlab.token",
		"email": "gitlab.email",
	})
	require.NoError(t, err)

	// Verify independent precedence per key:
	// - url: env var overrides file (no flag)
	// - token: flag overrides file (no env var)
	// - email: file is used (no flag, no env var)
	assert.Equal(t, "https://gitlab-env.com", GetString("gitlab.url"), "Env var should override for url key")
	assert.Equal(t, "flag-token", GetString("gitlab.token"), "CLI flag should override for token key")
	assert.Equal(t, "file@example.com", GetString("gitlab.email"), "Config file should be used for email key")
}
