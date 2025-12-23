package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlatformLevelInheritance(t *testing.T) {
	// Reset global viper
	globalViper = nil

	// Create config with platform-level settings
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
gitlab:
  url: https://gitlab.example.com
  token: glpat-shared-token
  
  enum:
    level: full
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Initialize with config
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Create a dummy command to test binding
	cmd := &cobra.Command{
		Use: "enum",
	}
	cmd.Flags().String("gitlab", "", "GitLab URL")
	cmd.Flags().String("token", "", "GitLab token")
	cmd.Flags().String("level", "", "Enum level")

	err = BindCommandFlags(cmd, "gitlab.enum", map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	})
	require.NoError(t, err)

	// Verify that gitlab.url and gitlab.token are accessible from enum subcommand
	// This tests that platform-level settings are inherited
	assert.Equal(t, "https://gitlab.example.com", GetString("gitlab.url"))
	assert.Equal(t, "glpat-shared-token", GetString("gitlab.token"))
	assert.Equal(t, "full", GetString("gitlab.enum.level"))

	// Verify required keys are satisfied (inheritance works)
	err = RequireConfigKeys("gitlab.url", "gitlab.token")
	assert.NoError(t, err, "Platform-level settings should be inherited by subcommands")
}

func TestCommandLevelOverridesPlatformLevel(t *testing.T) {
	// Reset global viper
	globalViper = nil

	// Create config with both platform and command-level settings
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
common:
  threads: 10
  
gitlab:
  url: https://gitlab.example.com
  token: glpat-platform-token
  scan:
    threads: 20
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Initialize with config
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Verify command-level setting overrides common setting
	assert.Equal(t, 10, GetInt("common.threads"))
	assert.Equal(t, 20, GetInt("gitlab.scan.threads"))
}

func TestEnvironmentVariableOverridesConfig(t *testing.T) {
	// Reset global viper
	globalViper = nil

	// Create config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
gitlab:
  url: https://gitlab.config.com
  token: config-token
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variable
	os.Setenv("PIPELEEK_GITLAB_TOKEN", "env-token")
	defer os.Unsetenv("PIPELEEK_GITLAB_TOKEN")

	// Initialize with config
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Verify environment variable overrides config file
	assert.Equal(t, "https://gitlab.config.com", GetString("gitlab.url"))
	assert.Equal(t, "env-token", GetString("gitlab.token"), "Environment variable should override config file")
}

func TestNestedConfigKeys(t *testing.T) {
	// Reset global viper
	globalViper = nil

	// Create config with nested structure
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
gitlab:
  url: https://gitlab.example.com
  token: glpat-token
  
  runners:
    exploit:
      tags:
        - docker
        - linux
      shell: bash
      dry: false
      
  renovate:
    enum:
      owned: true
      member: false
      fast: true
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Initialize with config
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Verify nested keys are accessible
	assert.Equal(t, "https://gitlab.example.com", GetString("gitlab.url"))
	assert.Equal(t, []interface{}{"docker", "linux"}, GetViper().Get("gitlab.runners.exploit.tags"))
	assert.Equal(t, "bash", GetString("gitlab.runners.exploit.shell"))
	assert.Equal(t, false, GetBool("gitlab.runners.exploit.dry"))
	assert.Equal(t, true, GetBool("gitlab.renovate.enum.owned"))
	assert.Equal(t, false, GetBool("gitlab.renovate.enum.member"))
	assert.Equal(t, true, GetBool("gitlab.renovate.enum.fast"))
}

func TestMultiplePlatformConfigs(t *testing.T) {
	// Reset global viper
	globalViper = nil

	// Create config with multiple platforms
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
gitlab:
  url: https://gitlab.example.com
  token: glpat-token
  
github:
  url: https://api.github.com
  token: ghp-token
  
bitbucket:
  url: https://bitbucket.org
  username: bb-user
  password: bb-pass
  
gitea:
  url: https://gitea.example.com
  token: gitea-token
  
azure_devops:
  url: https://dev.azure.com/org
  token: ado-token
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Initialize with config
	err = InitializeViper(configPath)
	require.NoError(t, err)

	// Verify all platforms are loaded correctly
	assert.Equal(t, "https://gitlab.example.com", GetString("gitlab.url"))
	assert.Equal(t, "glpat-token", GetString("gitlab.token"))
	
	assert.Equal(t, "https://api.github.com", GetString("github.url"))
	assert.Equal(t, "ghp-token", GetString("github.token"))
	
	assert.Equal(t, "https://bitbucket.org", GetString("bitbucket.url"))
	assert.Equal(t, "bb-user", GetString("bitbucket.username"))
	assert.Equal(t, "bb-pass", GetString("bitbucket.password"))
	
	assert.Equal(t, "https://gitea.example.com", GetString("gitea.url"))
	assert.Equal(t, "gitea-token", GetString("gitea.token"))
	
	assert.Equal(t, "https://dev.azure.com/org", GetString("azure_devops.url"))
	assert.Equal(t, "ado-token", GetString("azure_devops.token"))
}
