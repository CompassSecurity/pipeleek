package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_NoFile(t *testing.T) {
	// Reset global config
	globalConfig = nil
	
	config, err := LoadConfig("")
	require.NoError(t, err)
	require.NotNil(t, config)
	
	// Check defaults are set
	assert.Equal(t, 4, config.Common.Threads)
	assert.Equal(t, true, config.Common.TruffleHogVerification)
	assert.Equal(t, "500Mb", config.Common.MaxArtifactSize)
	assert.Equal(t, "https://api.github.com", config.GitHub.URL)
}

func TestLoadConfig_WithYAML(t *testing.T) {
	// Reset global config
	globalConfig = nil
	
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
	
	config, err := LoadConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, config)
	
	// Verify GitLab config
	assert.Equal(t, "https://gitlab.example.com", config.GitLab.URL)
	assert.Equal(t, "glpat-test-token", config.GitLab.Token)
	assert.Equal(t, "test-cookie", config.GitLab.Cookie)
	
	// Verify GitHub config
	assert.Equal(t, "https://github.example.com", config.GitHub.URL)
	assert.Equal(t, "ghp_test_token", config.GitHub.Token)
	
	// Verify BitBucket config
	assert.Equal(t, "https://bitbucket.example.com", config.BitBucket.URL)
	assert.Equal(t, "testuser", config.BitBucket.Username)
	assert.Equal(t, "testpass", config.BitBucket.Password)
	
	// Verify Azure DevOps config
	assert.Equal(t, "https://dev.azure.com", config.AzureDevOps.URL)
	assert.Equal(t, "azdo-token", config.AzureDevOps.Token)
	
	// Verify Gitea config
	assert.Equal(t, "https://gitea.example.com", config.Gitea.URL)
	assert.Equal(t, "gitea-token", config.Gitea.Token)
	
	// Verify common config
	assert.Equal(t, 8, config.Common.Threads)
	assert.Equal(t, false, config.Common.TruffleHogVerification)
	assert.Equal(t, "1GB", config.Common.MaxArtifactSize)
	assert.Equal(t, []string{"high", "medium"}, config.Common.ConfidenceFilter)
	assert.Equal(t, "120s", config.Common.HitTimeout)
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	// Reset global config
	globalConfig = nil
	
	config, err := LoadConfig("/nonexistent/path/to/config.yaml")
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	// Reset global config
	globalConfig = nil
	
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
	
	config, err := LoadConfig(configFile)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestGetConfig(t *testing.T) {
	// Reset global config
	globalConfig = nil
	
	config := GetConfig()
	require.NotNil(t, config)
	
	// Check that subsequent calls return the same instance
	config2 := GetConfig()
	assert.Equal(t, config, config2)
}

func TestLoadConfig_PartialConfig(t *testing.T) {
	// Reset global config
	globalConfig = nil
	
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
	
	config, err := LoadConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, config)
	
	// Verify GitLab is loaded
	assert.Equal(t, "https://gitlab.example.com", config.GitLab.URL)
	assert.Equal(t, "glpat-test", config.GitLab.Token)
	
	// Verify defaults are still applied
	assert.Equal(t, 4, config.Common.Threads)
	assert.Equal(t, "https://api.github.com", config.GitHub.URL)
}

func TestLoadConfig_EmptyValues(t *testing.T) {
	// Reset global config
	globalConfig = nil
	
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "empty.yaml")
	
	configContent := `
gitlab:
  url: ""
  token: ""
`
	
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)
	
	config, err := LoadConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, config)
	
	// Empty strings should be preserved (not replaced with defaults)
	assert.Equal(t, "", config.GitLab.URL)
	assert.Equal(t, "", config.GitLab.Token)
}
