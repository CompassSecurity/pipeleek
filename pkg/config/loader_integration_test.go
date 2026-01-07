package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/enum"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigSatisfiesRequiredFlags(t *testing.T) {
	// Ensure config file loading is enabled for this test
	os.Unsetenv("PIPELEEK_NO_CONFIG")
	defer os.Setenv("PIPELEEK_NO_CONFIG", os.Getenv("PIPELEEK_NO_CONFIG"))
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
gitlab:
  url: https://gitlab.example.com
  token: glpat-test-token-12345
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Initialize viper with the config file
	err = config.InitializeViper(configPath)
	require.NoError(t, err)

	// Create enum command
	cmd := enum.NewEnumCmd()

	// Bind flags (simulating what happens when command runs)
	err = config.BindCommandFlags(cmd, "gitlab.enum", map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	})
	require.NoError(t, err)

	// Verify required keys are satisfied from config file
	err = config.RequireConfigKeys("gitlab.url", "gitlab.token")
	assert.NoError(t, err, "Config file should satisfy required keys without CLI flags")

	// Verify values are accessible
	gitlabURL := config.GetString("gitlab.url")
	assert.Equal(t, "https://gitlab.example.com", gitlabURL)

	token := config.GetString("gitlab.token")
	assert.Equal(t, "glpat-test-token-12345", token)
}

func TestEnvironmentVariablesSatisfyRequiredFlags(t *testing.T) {
	// Ensure config file loading is enabled for this test
	os.Unsetenv("PIPELEEK_NO_CONFIG")
	defer os.Setenv("PIPELEEK_NO_CONFIG", os.Getenv("PIPELEEK_NO_CONFIG"))
	// Create temp config (even empty) to initialize Viper properly
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	err := os.WriteFile(configPath, []byte(""), 0644)
	require.NoError(t, err)

	// Set environment variables
	os.Setenv("PIPELEEK_GITLAB_URL", "https://gitlab.envtest.com")
	os.Setenv("PIPELEEK_GITLAB_TOKEN", "env-token-67890")
	defer func() {
		os.Unsetenv("PIPELEEK_GITLAB_URL")
		os.Unsetenv("PIPELEEK_GITLAB_TOKEN")
	}()

	// Initialize Viper (will pick up env vars)
	err = config.InitializeViper(configPath)
	require.NoError(t, err)

	// Create enum command
	cmd := enum.NewEnumCmd()

	// Bind flags
	err = config.BindCommandFlags(cmd, "gitlab.enum", map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	})
	require.NoError(t, err)

	// Verify required keys are satisfied from environment
	err = config.RequireConfigKeys("gitlab.url", "gitlab.token")
	assert.NoError(t, err, "Environment variables should satisfy required keys")

	// Verify values from environment
	gitlabURL := config.GetString("gitlab.url")
	assert.Equal(t, "https://gitlab.envtest.com", gitlabURL)

	token := config.GetString("gitlab.token")
	assert.Equal(t, "env-token-67890", token)
}

func TestFlagPriorityOverConfig(t *testing.T) {
	// Ensure config file loading is enabled for this test
	os.Unsetenv("PIPELEEK_NO_CONFIG")
	defer os.Setenv("PIPELEEK_NO_CONFIG", os.Getenv("PIPELEEK_NO_CONFIG"))
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
gitlab:
  url: https://gitlab.config.com
  token: config-token
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Initialize viper with the config file
	err = config.InitializeViper(configPath)
	require.NoError(t, err)

	// Create enum command
	cmd := enum.NewEnumCmd()

	// Simulate setting flags manually
	err = cmd.Flags().Set("gitlab", "https://gitlab.flag.com")
	require.NoError(t, err)
	err = cmd.Flags().Set("token", "flag-token")
	require.NoError(t, err)

	// Bind flags (flag values should take precedence)
	err = config.BindCommandFlags(cmd, "gitlab.enum", map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	})
	require.NoError(t, err)

	// Verify flag values take priority over config
	gitlabURL := config.GetString("gitlab.url")
	assert.Equal(t, "https://gitlab.flag.com", gitlabURL, "Flag value should override config")

	token := config.GetString("gitlab.token")
	assert.Equal(t, "flag-token", token, "Flag value should override config")
}

func TestMissingRequiredKeysProducesError(t *testing.T) {
	// Ensure config file loading is enabled for this test
	os.Unsetenv("PIPELEEK_NO_CONFIG")
	defer os.Setenv("PIPELEEK_NO_CONFIG", os.Getenv("PIPELEEK_NO_CONFIG"))
	// Create empty config to initialize Viper
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	err := os.WriteFile(configPath, []byte(""), 0644)
	require.NoError(t, err)

	// Initialize with empty config
	err = config.InitializeViper(configPath)
	require.NoError(t, err)

	// Create a dummy command
	cmd := &cobra.Command{
		Use: "test",
	}
	cmd.Flags().String("gitlab", "", "GitLab URL")
	cmd.Flags().String("token", "", "GitLab token")

	// Bind flags without setting any values
	err = config.BindCommandFlags(cmd, "gitlab.test", map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	})
	require.NoError(t, err)

	// Verify RequireConfigKeys reports missing keys
	err = config.RequireConfigKeys("gitlab.url", "gitlab.token")
	assert.Error(t, err, "Should error when required keys are missing")
	assert.Contains(t, err.Error(), "required configuration missing")
}
