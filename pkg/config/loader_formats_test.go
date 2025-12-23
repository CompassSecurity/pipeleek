package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitializeViper_JSONFormat(t *testing.T) {
	// Reset global viper
	globalViper = nil

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")

	configContent := `{
  "gitlab": {
    "url": "https://gitlab.json.com",
    "token": "glpat-json-token"
  },
  "common": {
    "threads": 12,
    "trufflehog_verification": false
  }
}`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	err = InitializeViper(configFile)
	require.NoError(t, err)

	// Verify JSON config was loaded
	assert.Equal(t, "https://gitlab.json.com", GetString("gitlab.url"))
	assert.Equal(t, "glpat-json-token", GetString("gitlab.token"))
	assert.Equal(t, 12, GetInt("common.threads"))
	assert.Equal(t, false, GetBool("common.trufflehog_verification"))
}

func TestInitializeViper_TOMLFormat(t *testing.T) {
	// Reset global viper
	globalViper = nil

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.toml")

	configContent := `[gitlab]
url = "https://gitlab.toml.com"
token = "glpat-toml-token"

[common]
threads = 16
trufflehog_verification = true
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	err = InitializeViper(configFile)
	require.NoError(t, err)

	// Verify TOML config was loaded
	assert.Equal(t, "https://gitlab.toml.com", GetString("gitlab.url"))
	assert.Equal(t, "glpat-toml-token", GetString("gitlab.token"))
	assert.Equal(t, 16, GetInt("common.threads"))
	assert.Equal(t, true, GetBool("common.trufflehog_verification"))
}

func TestConfigFileSearchOrder(t *testing.T) {
	// Reset global viper
	globalViper = nil

	// Create temp directory structure mimicking home directory
	tmpDir := t.TempDir()

	// Set HOME to temp directory for this test
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// Create config in ~/.config/pipeleek/config.yaml (should be found first)
	configDir := filepath.Join(tmpDir, ".config", "pipeleek")
	err := os.MkdirAll(configDir, 0755)
	require.NoError(t, err)

	priorityConfigPath := filepath.Join(configDir, "pipeleek.yaml")
	priorityConfig := `
gitlab:
  url: https://priority-config.com
  token: priority-token
`
	err = os.WriteFile(priorityConfigPath, []byte(priorityConfig), 0644)
	require.NoError(t, err)

	// Also create a config in ~ (should be ignored due to priority)
	homeConfigPath := filepath.Join(tmpDir, ".pipeleek.yaml")
	homeConfig := `
gitlab:
  url: https://home-config.com
  token: home-token
`
	err = os.WriteFile(homeConfigPath, []byte(homeConfig), 0644)
	require.NoError(t, err)

	// Initialize without explicit path (should find ~/.config/pipeleek/pipeleek.yaml)
	err = InitializeViper("")
	require.NoError(t, err)

	// Verify the priority config was loaded (not the home config)
	assert.Equal(t, "https://priority-config.com", GetString("gitlab.url"))
	assert.Equal(t, "priority-token", GetString("gitlab.token"))
}

func TestConfigFileCurrentDirectory(t *testing.T) {
	// Reset global viper
	globalViper = nil

	// Create temp directory and change to it
	tmpDir := t.TempDir()
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalDir)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Create config in current directory
	configPath := filepath.Join(tmpDir, "pipeleek.yaml")
	configContent := `
gitlab:
  url: https://current-dir.com
  token: current-dir-token
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Initialize without explicit path (should find ./pipeleek.yaml)
	err = InitializeViper("")
	require.NoError(t, err)

	// Verify current directory config was loaded
	assert.Equal(t, "https://current-dir.com", GetString("gitlab.url"))
	assert.Equal(t, "current-dir-token", GetString("gitlab.token"))
}
