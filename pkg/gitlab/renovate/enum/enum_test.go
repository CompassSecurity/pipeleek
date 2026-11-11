package renovate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/filter"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestProcessProjectsConcurrentlyUsesBoundedWorkers(t *testing.T) {
	resetStatus()
	projectCount := projectProcessingConcurrency * 3
	projects := make([]*gitlab.Project, projectCount)
	for i := range projects {
		projects[i] = &gitlab.Project{ID: int64(i + 1)}
	}

	started := make(chan struct{}, projectCount)
	release := make(chan struct{})
	var active atomic.Int32
	var maximumActive atomic.Int32
	var processed atomic.Int32
	done := make(chan error, 1)

	go func() {
		done <- processProjectsConcurrently(func(visit util.ProjectIteratorFunc) error {
			for _, project := range projects {
				if err := visit(project); err != nil {
					return err
				}
			}
			return nil
		}, func(*gitlab.Project) {
			current := active.Add(1)
			for previous := maximumActive.Load(); current > previous && !maximumActive.CompareAndSwap(previous, current); previous = maximumActive.Load() {
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			processed.Add(1)
		})
	}()

	for i := 0; i < projectProcessingConcurrency; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("workers did not start concurrently")
		}
	}
	close(release)
	require.NoError(t, <-done)
	assert.Equal(t, int32(projectProcessingConcurrency), maximumActive.Load())
	assert.Equal(t, int32(projectCount), processed.Load())
	assert.Equal(t, int64(projectCount), statusTracker.projectsDiscovered.Load())
	assert.Equal(t, int64(projectCount), statusTracker.projectsProcessed.Load())
}

func TestStatusHookReportsProgress(t *testing.T) {
	resetStatus()
	statusTracker.projectsDiscovered.Store(8)
	statusTracker.projectsProcessed.Store(5)
	statusTracker.renovateConfigsFound.Store(2)

	var output bytes.Buffer
	oldLogger := log.Logger
	log.Logger = zerolog.New(&output)
	defer func() { log.Logger = oldLogger }()

	StatusHook().Msg("Status")
	for _, field := range []string{
		`"projectsDiscovered":8`,
		`"projectsProcessed":5`,
		`"projectsOutstanding":3`,
		`"renovateConfigsFound":2`,
	} {
		assert.True(t, strings.Contains(output.String(), field), "status output missing %s: %s", field, output.String())
	}
}

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
		{"autodiscover quoted false env", `RENOVATE_AUTODISCOVER: 'false'`, "", false},
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
			name:        "filter in quoted RENOVATE_EXTRA_FLAGS",
			cicd:        `RENOVATE_EXTRA_FLAGS: "--autodiscover-filter=+(migzu|migzu-renovate|migzu-projects)*/*"`,
			expectFound: true,
			expectType:  "autodiscoverFilter",
			expectValue: "+(migzu|migzu-renovate|migzu-projects)*/*",
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
	opts := EnumOptions{SelfHostedOptions: []string{"self-hosted", "custom-platform", "autodiscoverFilter"}}

	tests := []struct {
		name           string
		configContent  string
		expectedResult bool
	}{
		{"contains self-hosted", `{"platform": "self-hosted"}`, true},
		{"contains custom-platform", `endpoint: custom-platform`, true},
		{"contains autodiscoverFilter", `{"autodiscoverFilter": ["group/**"]}`, true},
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

func TestVulnerableFindingRuleID(t *testing.T) {
	tests := []struct {
		name     string
		findings []filter.Finding
		wantRule string
		wantOK   bool
	}{
		{
			name:   "empty findings returns false",
			wantOK: false,
		},
		{
			name:     "single Vulnerable finding",
			findings: []filter.Finding{{RuleID: filter.RuleIDUnanchoredRegex, Verdict: filter.Vulnerable}},
			wantRule: filter.RuleIDUnanchoredRegex,
			wantOK:   true,
		},
		{
			name:     "single NeedsReview finding",
			findings: []filter.Finding{{RuleID: filter.RuleIDRegexEngineReview, Verdict: filter.NeedsReview}},
			wantOK:   false,
		},
		{
			name:     "only Safe findings returns false",
			findings: []filter.Finding{{RuleID: filter.RuleIDInfo, Verdict: filter.Safe}},
			wantOK:   false,
		},
		{
			name:     "only Broken findings returns false",
			findings: []filter.Finding{{RuleID: filter.RuleIDLeadingSlashGlob, Verdict: filter.Broken}},
			wantOK:   false,
		},
		{
			name: "Vulnerable beats NeedsReview",
			findings: []filter.Finding{
				{RuleID: filter.RuleIDRegexEngineReview, Verdict: filter.NeedsReview},
				{RuleID: filter.RuleIDPathBoundaryBypass, Verdict: filter.Vulnerable},
			},
			wantRule: filter.RuleIDPathBoundaryBypass,
			wantOK:   true,
		},
		{
			name: "Broken and NeedsReview returns false",
			findings: []filter.Finding{
				{RuleID: filter.RuleIDInfo, Verdict: filter.Safe},
				{RuleID: filter.RuleIDRegexEngineReview, Verdict: filter.NeedsReview},
				{RuleID: filter.RuleIDLeadingSlashGlob, Verdict: filter.Broken},
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := vulnerableFindingRuleID(tt.findings)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantRule, got)
			}
		})
	}
}

func TestHasEffectiveAutodiscoveryScope(t *testing.T) {
	tests := []struct {
		name       string
		filterType string
		value      string
		want       bool
	}{
		{name: "nonempty autodiscover filter", filterType: "autodiscoverFilter", value: "group/**", want: true},
		{name: "empty autodiscover filter", filterType: "autodiscoverFilter", value: "", want: false},
		{name: "null autodiscover filter", filterType: "autodiscoverFilter", value: "<nil>", want: false},
		{name: "empty autodiscover filter array", filterType: "autodiscoverFilter", value: "[]", want: false},
		{name: "blank autodiscover filter array", filterType: "autodiscoverFilter", value: `["", "  "]`, want: false},
		{name: "nonempty namespaces", filterType: "autodiscoverNamespaces", value: `["group"]`, want: true},
		{name: "empty namespaces", filterType: "autodiscoverNamespaces", value: "[]", want: false},
		{name: "null namespaces", filterType: "autodiscoverNamespaces", value: "<nil>", want: false},
		{name: "nonempty topics", filterType: "autodiscoverTopics", value: `["managed"]`, want: true},
		{name: "empty topics", filterType: "autodiscoverTopics", value: "[]", want: false},
		{name: "null topics", filterType: "autodiscoverTopics", value: "<nil>", want: false},
		{name: "projects are unsupported on GitLab", filterType: "autodiscoverProjects", value: `["project"]`, want: false},
		{name: "empty projects are unsupported on GitLab", filterType: "autodiscoverProjects", value: "[]", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasEffectiveAutodiscoveryScope(tt.filterType, tt.value))
		})
	}
}

func TestCommaDelimitedFilterPatterns(t *testing.T) {
	filterValue := "branchbooks/*, *"
	analysisValue := commaDelimitedFilterPatterns(filterValue)
	assert.Equal(t, `["branchbooks/*","*"]`, analysisValue)
	findings := filter.Analyze(analysisValue)
	for _, finding := range findings {
		if finding.RuleID == filter.RuleIDUnrestrictedWildcard {
			return
		}
	}
	t.Fatal("expected the comma-separated bare wildcard to be detected")
}
