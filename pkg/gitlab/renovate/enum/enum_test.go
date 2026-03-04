package renovate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestExtractSelfHostedOptions(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []string
	}{
		{
			name: "extracts single option",
			input: []byte(`## selfHostedType
Description here`),
			expected: []string{"selfHostedType"},
		},
		{
			name: "extracts multiple options",
			input: []byte(`## option1
Some text
## option2
More text
## option3
Even more text`),
			expected: []string{"option1", "option2", "option3"},
		},
		{
			name:     "returns empty for no matches",
			input:    []byte("No matching content here"),
			expected: []string{},
		},
		{
			name: "handles options with special characters",
			input: []byte(`## self-hosted-type
## selfHosted_Type
## selfHosted.Type`),
			expected: []string{"self-hosted-type", "selfHosted_Type", "selfHosted.Type"},
		},
		{
			name: "ignores non-## headers",
			input: []byte(`# Level 1 Header
## option1
### Level 3 Header
## option2`),
			expected: []string{"option1", "Level 3 Header", "option2"}, // ## .* matches ### as well
		},
		{
			name:     "handles empty input",
			input:    []byte(""),
			expected: []string{},
		},
		{
			name: "handles whitespace around markers",
			input: []byte(`   ## option1   
Some text
		## option2		
More text`),
			expected: []string{"option1", "option2"},
		},
		{
			name: "extracts real renovate options",
			input: []byte(`## allowCustomCrateRegistries
## allowPlugins
## allowPostUpgradeCommandTemplating
## allowScripts
## allowedPostUpgradeCommands`),
			expected: []string{
				"allowCustomCrateRegistries",
				"allowPlugins",
				"allowPostUpgradeCommandTemplating",
				"allowScripts",
				"allowedPostUpgradeCommands",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSelfHostedOptions(tt.input)

			if len(tt.expected) == 0 {
				assert.Empty(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestExtractSelfHostedOptions_RealWorld(t *testing.T) {
	t.Run("parses markdown documentation format", func(t *testing.T) {
		markdown := []byte(`# Self-hosted options

These options are only applicable for self-hosted Renovate instances.

## platform
Platform type of SCM. Options: github, gitlab, bitbucket, azure.

## endpoint
API endpoint for the platform.

## binarySource
Controls where Renovate installs binaries.`)

		result := extractSelfHostedOptions(markdown)
		expected := []string{"platform", "endpoint", "binarySource"}
		assert.Equal(t, expected, result)
	})
}

func TestValidateOrderBy(t *testing.T) {
	tests := []struct {
		name        string
		orderBy     string
		expectError bool
	}{
		{"accepts id", "id", false},
		{"accepts name", "name", false},
		{"accepts path", "path", false},
		{"accepts created_at", "created_at", false},
		{"accepts updated_at", "updated_at", false},
		{"accepts star_count", "star_count", false},
		{"accepts last_activity_at", "last_activity_at", false},
		{"accepts similarity", "similarity", false},
		{"rejects invalid value", "random", true},
		{"rejects empty string", "", true},
		{"rejects uppercase variant", "Name", true},
		{"rejects SQL injection attempt", "id; DROP TABLE", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOrderBy(tt.orderBy)
			if tt.expectError {
				assert.Error(t, err, "expected error for orderBy=%q", tt.orderBy)
			} else {
				assert.NoError(t, err, "expected no error for orderBy=%q", tt.orderBy)
			}
		})
	}
}

func TestValidOrderByValues(t *testing.T) {
	validValues := []string{
		"id", "name", "path", "created_at",
		"updated_at", "star_count", "last_activity_at", "similarity",
	}

	for _, value := range validValues {
		t.Run("validates_"+value, func(t *testing.T) {
			assert.NoError(t, validateOrderBy(value), "orderBy=%s should be valid", value)
		})
	}
}

func TestDetectCiCdConfig(t *testing.T) {
	tests := []struct {
		name     string
		cicdConf string
		expected bool
	}{
		{"renovate/renovate image", "image: renovate/renovate:latest", true},
		{"renovatebot/renovate image", "image: renovatebot/renovate", true},
		{"renovate-bot runner", "image: renovate-bot/renovate-runner", true},
		{"RENOVATE_ env var", "RENOVATE_TOKEN: secret", true},
		{"npx renovate", "script: npx renovate", true},
		{"no renovate", "image: node:14", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectCiCdConfig(tt.cicdConf)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectAutodiscovery(t *testing.T) {
	tests := []struct {
		name              string
		cicdConf          string
		configFileContent string
		expected          bool
	}{
		{"autodiscover in config", "", `{"autodiscover": true}`, true},
		{"--autodiscover flag", "--autodiscover", "", true},
		{"RENOVATE_AUTODISCOVER env", "RENOVATE_AUTODISCOVER: true", "", true},
		{"autodiscover disabled", "--autodiscover=false", "", false},
		{"autodiscover false env", "RENOVATE_AUTODISCOVER: false", "", false},
		{"no autodiscover", "image: renovate", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectAutodiscovery(tt.cicdConf, tt.configFileContent)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectAutodiscoveryFilters(t *testing.T) {
	tests := []struct {
		name        string
		cicd        string
		config      string
		expectFound bool
		expectType  string
		expectValue string
	}{
		{
			name:        "autodiscoverFilter in config YAML",
			cicd:        "",
			config:      `autodiscoverFilter: "group/project"`,
			expectFound: true,
			expectType:  "autodiscoverFilter",
			expectValue: `group/project`,
		},
		{
			name:        "RENOVATE_AUTODISCOVER_FILTER env",
			cicd:        "RENOVATE_AUTODISCOVER_FILTER=mygroup/*",
			config:      "",
			expectFound: true,
			expectType:  "autodiscoverFilter",
			expectValue: "mygroup/*",
		},
		{
			name:        "autodiscoverNamespaces flag",
			cicd:        "--autodiscover-namespaces team-a",
			config:      "",
			expectFound: true,
			expectType:  "autodiscoverNamespaces",
			expectValue: "team-a",
		},
		{
			name:        "autodiscoverProjects in config",
			cicd:        "",
			config:      `autodiscoverProjects: ["proj1", "proj2"]`,
			expectFound: true,
			expectType:  "autodiscoverProjects",
			expectValue: `["proj1", "proj2"]`,
		},
		{
			name:        "autodiscoverTopics env",
			cicd:        "RENOVATE_AUTODISCOVER_TOPICS: security",
			config:      "",
			expectFound: true,
			expectType:  "autodiscoverTopics",
			expectValue: "security",
		},
		{
			name:        "no filters",
			cicd:        "image: renovate",
			config:      "{}",
			expectFound: false,
			expectType:  "",
			expectValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, filterType, filterValue := detectAutodiscoveryFilters(tt.cicd, tt.config)
			assert.Equal(t, tt.expectFound, found)
			assert.Equal(t, tt.expectType, filterType)
			assert.Equal(t, tt.expectValue, filterValue)
		})
	}
}

func TestIsSelfHostedConfig(t *testing.T) {
	opts := EnumOptions{SelfHostedOptions: []string{"self-hosted", "custom-platform"}}

	tests := []struct {
		name           string
		configContent  string
		expectedResult bool
	}{
		{"contains self-hosted", `{"platform": "self-hosted"}`, true},
		{"contains custom-platform", `endpoint: custom-platform`, true},
		{"no self-hosted", `{"platform": "github"}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSelfHostedConfig(tt.configContent, opts)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestDumpConfigFileContents_CreatesFiles(t *testing.T) {
	tmpDir := t.TempDir()
	project := &gitlab.Project{PathWithNamespace: "myorg/myproject"}

	dumpConfigFileContents(project, "# CI/CD YAML content", `{"extends":["config:base"]}`, "renovate.json", tmpDir)

	// Verify CI/CD YAML was written
	ciCdPath := filepath.Join(tmpDir, "myorg", "myproject", "gitlab-ci.yml")
	data, err := os.ReadFile(ciCdPath)
	require.NoError(t, err)
	assert.Equal(t, "# CI/CD YAML content", string(data))

	// Verify renovate config was written
	configPath := filepath.Join(tmpDir, "myorg", "myproject", "renovate.json")
	data, err = os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, `{"extends":["config:base"]}`, string(data))
}

func TestDumpConfigFileContents_DefaultsFilenameToRenovateJSON(t *testing.T) {
	tmpDir := t.TempDir()
	project := &gitlab.Project{PathWithNamespace: "org/repo"}

	// Empty filename should default to renovate.json
	dumpConfigFileContents(project, "", `{"key":"val"}`, "", tmpDir)

	configPath := filepath.Join(tmpDir, "org", "repo", "renovate.json")
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, `{"key":"val"}`, string(data))
}

func TestDumpConfigFileContents_SkipsEmptyContent(t *testing.T) {
	tmpDir := t.TempDir()
	project := &gitlab.Project{PathWithNamespace: "org/repo"}

	// Both cicd and config are empty: files should NOT be created
	dumpConfigFileContents(project, "", "", "renovate.json", tmpDir)

	ciCdPath := filepath.Join(tmpDir, "org", "repo", "gitlab-ci.yml")
	_, err := os.Stat(ciCdPath)
	assert.True(t, os.IsNotExist(err), "gitlab-ci.yml should not be created when ciCdYml is empty")

	configPath := filepath.Join(tmpDir, "org", "repo", "renovate.json")
	_, err = os.Stat(configPath)
	assert.True(t, os.IsNotExist(err), "renovate.json should not be created when content is empty")
}

func TestDumpConfigFileContents_OnlyCICD(t *testing.T) {
	tmpDir := t.TempDir()
	project := &gitlab.Project{PathWithNamespace: "org/repo"}

	dumpConfigFileContents(project, "ci: content", "", "", tmpDir)

	ciCdPath := filepath.Join(tmpDir, "org", "repo", "gitlab-ci.yml")
	data, err := os.ReadFile(ciCdPath)
	require.NoError(t, err)
	assert.Equal(t, "ci: content", string(data))

	// renovate.json should NOT be created
	configPath := filepath.Join(tmpDir, "org", "repo", "renovate.json")
	_, err = os.Stat(configPath)
	assert.True(t, os.IsNotExist(err))
}
