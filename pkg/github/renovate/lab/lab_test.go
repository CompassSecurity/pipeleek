package lab

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLabSetupConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  LabSetupConfig
		isValid bool
	}{
		{
			name:    "valid config",
			config:  LabSetupConfig{RepoName: "test-repo", Owner: "testuser"},
			isValid: true,
		},
		{
			name:    "empty repo name",
			config:  LabSetupConfig{RepoName: "", Owner: "testuser"},
			isValid: false,
		},
		{
			name:    "empty owner",
			config:  LabSetupConfig{RepoName: "test-repo", Owner: ""},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.config.RepoName != "" && tt.config.Owner != ""
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}

func TestRenovateConfigWithAutodiscovery(t *testing.T) {
	// Verify the config contains required settings
	assert.Contains(t, renovateConfigWithAutodiscovery, "autodiscover", "Config should enable autodiscover")
	assert.Contains(t, renovateConfigWithAutodiscovery, "autodiscoverFilter", "Config should have autodiscoverFilter")
	assert.Contains(t, renovateConfigWithAutodiscovery, "extends", "Config should extend base config")
	assert.Contains(t, renovateConfigWithAutodiscovery, "\"**\"", "Config should use wildcard filter")
}

func TestRenovateWorkflowYml(t *testing.T) {
	// Verify the workflow contains required settings
	assert.Contains(t, renovateWorkflowYml, "name: Renovate", "Workflow should have Renovate name")
	assert.Contains(t, renovateWorkflowYml, "renovatebot/github-action", "Workflow should use renovate action")
	assert.Contains(t, renovateWorkflowYml, "RENOVATE_LAB_TOKEN", "Workflow should use lab token secret")
	assert.Contains(t, renovateWorkflowYml, "schedule", "Workflow should have schedule trigger")
	assert.Contains(t, renovateWorkflowYml, "workflow_dispatch", "Workflow should support manual dispatch")
}

func TestLabConfigurationFiles(t *testing.T) {
	tests := []struct {
		name    string
		content string
		checks  []string
	}{
		{
			name:    "renovate.json config",
			content: renovateConfigWithAutodiscovery,
			checks: []string{
				"\"extends\"",
				"\"config:base\"",
				"\"autodiscover\": true",
				"\"autodiscoverFilter\"",
			},
		},
		{
			name:    "workflow file",
			content: renovateWorkflowYml,
			checks: []string{
				"name: Renovate",
				"schedule:",
				"workflow_dispatch:",
				"renovatebot/github-action",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, check := range tt.checks {
				assert.Contains(t, tt.content, check, "Config should contain %s", check)
			}
		})
	}
}
