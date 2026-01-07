package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPriorityOrder_FlagsOverEnvVars tests that CLI flags have highest priority over environment variables
func TestPriorityOrder_FlagsOverEnvVars(t *testing.T) {
	// Ensure config file loading is enabled for this test
	t.Setenv("PIPELEEK_NO_CONFIG", "")
	// Create empty config to initialize Viper
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	err := os.WriteFile(configPath, []byte(""), 0644)
	require.NoError(t, err)

	// Set environment variable
	os.Setenv("PIPELEEK_GITLAB_URL", "https://gitlab.env.com")
	defer os.Unsetenv("PIPELEEK_GITLAB_URL")

	// Initialize with config
	err = config.InitializeViper(configPath)
	require.NoError(t, err)

	// Create command and set flag
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("gitlab", "", "GitLab URL")
	err = cmd.Flags().Set("gitlab", "https://gitlab.flag.com")
	require.NoError(t, err)

	// Bind flags
	err = config.BindCommandFlags(cmd, "gitlab.test", map[string]string{
		"gitlab": "gitlab.url",
	})
	require.NoError(t, err)

	// Verify flag takes precedence over env var
	url := config.GetString("gitlab.url")
	assert.Equal(t, "https://gitlab.flag.com", url, "CLI flag should override environment variable")
}

// TestPriorityOrder_EnvVarsOverConfigFile tests that environment variables override config file
func TestPriorityOrder_EnvVarsOverConfigFile(t *testing.T) {
	// Ensure config file loading is enabled for this test
	t.Setenv("PIPELEEK_NO_CONFIG", "")
	// Create config file with a value
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	configContent := `
gitlab:
  url: https://gitlab.config.com
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variable
	os.Setenv("PIPELEEK_GITLAB_URL", "https://gitlab.env.com")
	defer os.Unsetenv("PIPELEEK_GITLAB_URL")

	// Initialize Viper
	err = config.InitializeViper(configPath)
	require.NoError(t, err)

	// Verify env var takes precedence over config file
	url := config.GetString("gitlab.url")
	assert.Equal(t, "https://gitlab.env.com", url, "Environment variable should override config file")
}

// TestPriorityOrder_ConfigFileOverDefaults tests that config file values override defaults
func TestPriorityOrder_ConfigFileOverDefaults(t *testing.T) {
	// Ensure config file loading is enabled for this test
	t.Setenv("PIPELEEK_NO_CONFIG", "")
	// Create config file with a value
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	configContent := `
common:
  threads: 20
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Initialize Viper (defaults are set in setDefaults())
	err = config.InitializeViper(configPath)
	require.NoError(t, err)

	// Verify config file value overrides default (default is 4)
	threads := config.GetInt("common.threads")
	assert.Equal(t, 20, threads, "Config file value should override default")
}

// TestPriorityOrder_FullChain tests the complete priority chain:
// CLI flags > Environment variables > Config file > Defaults
func TestPriorityOrder_FullChain(t *testing.T) {
	// Ensure config file loading is enabled for this test
	t.Setenv("PIPELEEK_NO_CONFIG", "")
	// Setup: Create config with threads=10
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	configContent := `
gitlab:
  url: https://gitlab.config.com
  token: config-token
common:
  threads: 10
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Setup: Set env var for gitlab.token
	os.Setenv("PIPELEEK_GITLAB_TOKEN", "env-token")
	defer os.Unsetenv("PIPELEEK_GITLAB_TOKEN")

	// Initialize Viper
	err = config.InitializeViper(configPath)
	require.NoError(t, err)

	// Setup: Create command with gitlab flag
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("gitlab", "", "GitLab URL")
	err = cmd.Flags().Set("gitlab", "https://gitlab.flag.com")
	require.NoError(t, err)

	// Bind flags
	err = config.BindCommandFlags(cmd, "gitlab.test", map[string]string{
		"gitlab": "gitlab.url",
	})
	require.NoError(t, err)

	// Test 1: CLI flag should override config file
	url := config.GetString("gitlab.url")
	assert.Equal(t, "https://gitlab.flag.com", url, "CLI flag > config file")

	// Test 2: Env var should override config file
	token := config.GetString("gitlab.token")
	assert.Equal(t, "env-token", token, "Environment variable > config file")

	// Test 3: Config file should override default (default threads is 4)
	threads := config.GetInt("common.threads")
	assert.Equal(t, 10, threads, "Config file > default")

	// Test 4: Default should be used when nothing else is set (trufflehog_verification default is true)
	verification := config.GetBool("common.trufflehog_verification")
	assert.Equal(t, true, verification, "Default value used when no override")
}

// TestConfigFileSearchOrder_Priority tests that files are found in documented order:
// 1. ~/.config/pipeleek/pipeleek.yaml
// 2. ~/pipeleek.yaml
// 3. ./pipeleek.yaml
func TestConfigFileSearchOrder_Priority(t *testing.T) {
	// Reset global viper
	config.ResetViper()
	// Ensure config file loading is enabled for this test
	t.Setenv("PIPELEEK_NO_CONFIG", "")

	// Create temp directory structure
	tmpDir := t.TempDir()
	tmpHome := filepath.Join(tmpDir, "home")
	tmpCwd := filepath.Join(tmpDir, "cwd")
	require.NoError(t, os.MkdirAll(tmpHome, 0755))
	require.NoError(t, os.MkdirAll(tmpCwd, 0755))

	// Set HOME and change to cwd
	originalHome := os.Getenv("HOME")
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		os.Setenv("HOME", originalHome)
		_ = os.Chdir(originalDir)
	}()

	os.Setenv("HOME", tmpHome)
	err = os.Chdir(tmpCwd)
	require.NoError(t, err)

	// Create all three config files with different values
	// 1. ~/.config/pipeleek/pipeleek.yaml (highest priority)
	configPipeLeekDir := filepath.Join(tmpHome, ".config", "pipeleek")
	require.NoError(t, os.MkdirAll(configPipeLeekDir, 0755))
	err = os.WriteFile(filepath.Join(configPipeLeekDir, "pipeleek.yaml"), []byte("gitlab:\n  url: https://config-pipeleek.com\n"), 0644)
	require.NoError(t, err)

	// 2. ~/pipeleek.yaml (second priority)
	err = os.WriteFile(filepath.Join(tmpHome, "pipeleek.yaml"), []byte("gitlab:\n  url: https://home.com\n"), 0644)
	require.NoError(t, err)

	// 3. ./pipeleek.yaml (lowest priority)
	err = os.WriteFile(filepath.Join(tmpCwd, "pipeleek.yaml"), []byte("gitlab:\n  url: https://current-dir.com\n"), 0644)
	require.NoError(t, err)

	// Initialize without explicit path
	err = config.InitializeViper("")
	require.NoError(t, err)

	// Should load ~/.config/pipeleek/pipeleek.yaml (highest priority)
	url := config.GetString("gitlab.url")
	assert.Equal(t, "https://config-pipeleek.com", url, "Should load from ~/.config/pipeleek/pipeleek.yaml first")
}

// TestConfigFileSearchOrder_SecondPriority tests that ~/pipeleek.yaml is used when ~/.config/pipeleek/ doesn't exist
func TestConfigFileSearchOrder_SecondPriority(t *testing.T) {
	// Reset global viper
	config.ResetViper()
	// Ensure config file loading is enabled for this test
	t.Setenv("PIPELEEK_NO_CONFIG", "")

	// Create temp directory
	tmpDir := t.TempDir()
	tmpHome := filepath.Join(tmpDir, "home")
	tmpCwd := filepath.Join(tmpDir, "cwd")
	require.NoError(t, os.MkdirAll(tmpHome, 0755))
	require.NoError(t, os.MkdirAll(tmpCwd, 0755))

	// Set HOME and change to cwd
	originalHome := os.Getenv("HOME")
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		os.Setenv("HOME", originalHome)
		_ = os.Chdir(originalDir)
	}()

	os.Setenv("HOME", tmpHome)
	err = os.Chdir(tmpCwd)
	require.NoError(t, err)

	// Only create ~/pipeleek.yaml and ./pipeleek.yaml (no ~/.config/pipeleek/)
	err = os.WriteFile(filepath.Join(tmpHome, "pipeleek.yaml"), []byte("gitlab:\n  url: https://home.com\n"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpCwd, "pipeleek.yaml"), []byte("gitlab:\n  url: https://current-dir.com\n"), 0644)
	require.NoError(t, err)

	// Initialize without explicit path
	err = config.InitializeViper("")
	require.NoError(t, err)

	// Should load ~/pipeleek.yaml (second priority)
	url := config.GetString("gitlab.url")
	assert.Equal(t, "https://home.com", url, "Should load from ~/pipeleek.yaml when ~/.config/pipeleek/ doesn't exist")
}

// TestConfigFileSearchOrder_CurrentDirectory tests that ./pipeleek.yaml is used as last resort
func TestConfigFileSearchOrder_CurrentDirectory(t *testing.T) {
	// Reset global viper
	config.ResetViper()
	// Ensure config file loading is enabled for this test
	t.Setenv("PIPELEEK_NO_CONFIG", "")

	// Create temp directory
	tmpDir := t.TempDir()
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalDir)
	}()

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Unset HOME to avoid finding files in home directory
	t.Setenv("HOME", "")

	// Only create ./pipeleek.yaml
	err = os.WriteFile(filepath.Join(tmpDir, "pipeleek.yaml"), []byte("gitlab:\n  url: https://current-dir.com\n"), 0644)
	require.NoError(t, err)

	// Initialize without explicit path
	err = config.InitializeViper("")
	require.NoError(t, err)

	// Should load ./pipeleek.yaml
	url := config.GetString("gitlab.url")
	assert.Equal(t, "https://current-dir.com", url, "Should load from ./pipeleek.yaml when no home configs exist")
}
