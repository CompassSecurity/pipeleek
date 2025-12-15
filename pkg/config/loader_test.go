package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitializeViper_NoFile(t *testing.T) {
	// Reset global viper
	globalViper = nil
	
	err := InitializeViper("")
	require.NoError(t, err)
	
	// Check defaults are set
	assert.Equal(t, 4, GetInt("common.threads"))
	assert.Equal(t, true, GetBool("common.trufflehog_verification"))
	assert.Equal(t, "500Mb", GetString("common.max_artifact_size"))
	assert.Equal(t, "https://api.github.com", GetString("github.url"))
}

func TestInitializeViper_WithYAML(t *testing.T) {
	// Reset global viper
	globalViper = nil
	
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test-config.yaml")
	
	configContent := `
gitlab:
  url: https://gitlab.example.com
  token: glpat-test-token
  cookie: test-cookie

github:
  url: https://github.example.com
  token: ghp_test_token

bitbucket:
  url: https://bitbucket.example.com
  username: testuser
  password: testpass

azure_devops:
  url: https://dev.azure.com
  token: azdo-token

gitea:
  url: https://gitea.example.com
  token: gitea-token

common:
  threads: 8
  trufflehog_verification: false
  max_artifact_size: 1GB
  confidence_filter:
    - high
    - medium
  hit_timeout: 120s
`
	
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)
	
	err = InitializeViper(configFile)
	require.NoError(t, err)
	
	// Verify GitLab config
	assert.Equal(t, "https://gitlab.example.com", GetString("gitlab.url"))
	assert.Equal(t, "glpat-test-token", GetString("gitlab.token"))
	assert.Equal(t, "test-cookie", GetString("gitlab.cookie"))
	
	// Verify GitHub config
	assert.Equal(t, "https://github.example.com", GetString("github.url"))
	assert.Equal(t, "ghp_test_token", GetString("github.token"))
	
	// Verify BitBucket config
	assert.Equal(t, "https://bitbucket.example.com", GetString("bitbucket.url"))
	assert.Equal(t, "testuser", GetString("bitbucket.username"))
	assert.Equal(t, "testpass", GetString("bitbucket.password"))
	
	// Verify Azure DevOps config
	assert.Equal(t, "https://dev.azure.com", GetString("azure_devops.url"))
	assert.Equal(t, "azdo-token", GetString("azure_devops.token"))
	
	// Verify Gitea config
	assert.Equal(t, "https://gitea.example.com", GetString("gitea.url"))
	assert.Equal(t, "gitea-token", GetString("gitea.token"))
	
	// Verify common config
	assert.Equal(t, 8, GetInt("common.threads"))
	assert.Equal(t, false, GetBool("common.trufflehog_verification"))
	assert.Equal(t, "1GB", GetString("common.max_artifact_size"))
	assert.Equal(t, []string{"high", "medium"}, GetStringSlice("common.confidence_filter"))
	assert.Equal(t, "120s", GetString("common.hit_timeout"))
}

func TestInitializeViper_InvalidFile(t *testing.T) {
	// Reset global viper
	globalViper = nil
	
	err := InitializeViper("/nonexistent/path/to/config.yaml")
	assert.Error(t, err)
}

func TestInitializeViper_InvalidYAML(t *testing.T) {
	// Reset global viper
	globalViper = nil
	
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid.yaml")
	
	invalidContent := `
gitlab:
  url: https://gitlab.com
  token: test
    invalid_indentation: here
`
	
	err := os.WriteFile(configFile, []byte(invalidContent), 0644)
	require.NoError(t, err)
	
	err = InitializeViper(configFile)
	assert.Error(t, err)
}

func TestGetViper(t *testing.T) {
	// Reset global viper
	globalViper = nil
	
	v := GetViper()
	require.NotNil(t, v)
	
	// Check that subsequent calls return the same instance
	v2 := GetViper()
	assert.Equal(t, v, v2)
}

func TestInitializeViper_PartialConfig(t *testing.T) {
	// Reset global viper
	globalViper = nil
	
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "partial.yaml")
	
	// Only set GitLab config, rest should use defaults
	configContent := `
gitlab:
  url: https://gitlab.example.com
  token: glpat-test
`
	
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)
	
	err = InitializeViper(configFile)
	require.NoError(t, err)
	
	// Verify GitLab is loaded
	assert.Equal(t, "https://gitlab.example.com", GetString("gitlab.url"))
	assert.Equal(t, "glpat-test", GetString("gitlab.token"))
	
	// Verify defaults are still applied
	assert.Equal(t, 4, GetInt("common.threads"))
	assert.Equal(t, "https://api.github.com", GetString("github.url"))
}

func TestInitializeViper_EmptyValues(t *testing.T) {
	// Reset global viper
	globalViper = nil
	
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "empty.yaml")
	
	configContent := `
gitlab:
  url: ""
  token: ""
`
	
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)
	
	err = InitializeViper(configFile)
	require.NoError(t, err)
	
	// Empty strings should be preserved (not replaced with defaults)
	assert.Equal(t, "", GetString("gitlab.url"))
	assert.Equal(t, "", GetString("gitlab.token"))
}
