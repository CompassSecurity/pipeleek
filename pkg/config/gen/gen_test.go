package gen_test

import (
	"strings"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config/gen"
	"gopkg.in/yaml.v3"
)

func TestGenerateExampleConfig_IsValidYAML(t *testing.T) {
	content := gen.GenerateExampleConfig()
	if content == "" {
		t.Fatal("GenerateExampleConfig returned empty string")
	}

	// Strip YAML comments so yaml.Unmarshal can parse it
	lines := strings.Split(content, "\n")
	var yamlLines []string
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Remove inline comments (after #) while preserving string values
		yamlLines = append(yamlLines, line)
	}
	yamlContent := strings.Join(yamlLines, "\n")

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &parsed); err != nil {
		t.Errorf("GenerateExampleConfig output is not valid YAML: %v", err)
	}
}

func TestGenerateExampleConfig_ContainsCommonKeys(t *testing.T) {
	content := gen.GenerateExampleConfig()

	requiredKeys := []string{
		"common:",
		"threads:",
		"trufflehog_verification:",
		"max_artifact_size:",
		"confidence_filter:",
		"hit_timeout:",
	}

	for _, key := range requiredKeys {
		if !strings.Contains(content, key) {
			t.Errorf("Expected config to contain %q", key)
		}
	}
}

func TestGenerateExampleConfig_ContainsPlatformKeys(t *testing.T) {
	content := gen.GenerateExampleConfig()

	platformKeys := []string{
		"gitlab:",
		"github:",
		"bitbucket:",
		"azure_devops:",
		"gitea:",
		"jenkins:",
		"circle:",
	}

	for _, key := range platformKeys {
		if !strings.Contains(content, key) {
			t.Errorf("Expected config to contain platform section %q", key)
		}
	}
}

func TestGenerateExampleConfig_CorrectDefaultTypes(t *testing.T) {
	content := gen.GenerateExampleConfig()

	// max_artifact_size should be a string "500Mb", not an integer
	if !strings.Contains(content, `max_artifact_size: "500Mb"`) {
		t.Error("Expected max_artifact_size to be the string \"500Mb\"")
	}

	// hit_timeout should be a duration string "60s", not an integer
	if !strings.Contains(content, `hit_timeout: "60s"`) {
		t.Error("Expected hit_timeout to be the string \"60s\"")
	}

	// confidence_filter should be an empty list, not a scalar string
	if !strings.Contains(content, "confidence_filter: []") {
		t.Error("Expected confidence_filter to be an empty list []")
	}
}

func TestGenerateExampleConfig_CorrectPriorityComment(t *testing.T) {
	content := gen.GenerateExampleConfig()

	// Check that environment variables are listed as priority #2 (above config file)
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, "Environment variables") {
			if !strings.Contains(line, "2.") {
				t.Errorf("Expected environment variables to be priority #2 at line %d: %q", i+1, line)
			}
		}
		if strings.Contains(line, "Configuration file") {
			if !strings.Contains(line, "3.") {
				t.Errorf("Expected configuration file to be priority #3 at line %d: %q", i+1, line)
			}
		}
	}
}

func TestGenerateExampleConfig_ScanSectionKeys(t *testing.T) {
	content := gen.GenerateExampleConfig()

	// gitlab scan keys
	gitlabScanKeys := []string{
		"gitlab.scan.search",
		"gitlab.scan.repo",
		"gitlab.scan.namespace",
		"gitlab.scan.artifacts",
		"gitlab.scan.owned",
	}
	for _, key := range gitlabScanKeys {
		// Convert dot-notation to what appears in the YAML comment
		envKey := "PIPELEEK_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
		if !strings.Contains(content, envKey) {
			t.Errorf("Expected config to contain env var reference for %q", envKey)
		}
	}

	// github scan keys
	githubScanKeys := []string{
		"PIPELEEK_GITHUB_SCAN_ORG",
		"PIPELEEK_GITHUB_SCAN_USER",
		"PIPELEEK_GITHUB_SCAN_SEARCH",
		"PIPELEEK_GITHUB_SCAN_REPO",
		"PIPELEEK_GITHUB_SCAN_PUBLIC",
		"PIPELEEK_GITHUB_SCAN_MAX_WORKFLOWS",
		"PIPELEEK_GITHUB_SCAN_ARTIFACTS",
		"PIPELEEK_GITHUB_SCAN_OWNED",
	}
	for _, key := range githubScanKeys {
		if !strings.Contains(content, key) {
			t.Errorf("Expected config to contain env var reference %q", key)
		}
	}

	// devops scan keys
	devopsScanKeys := []string{
		"PIPELEEK_AZURE_DEVOPS_USERNAME",
		"PIPELEEK_AZURE_DEVOPS_SCAN_ORGANIZATION",
		"PIPELEEK_AZURE_DEVOPS_SCAN_PROJECT",
		"PIPELEEK_AZURE_DEVOPS_SCAN_MAX_BUILDS",
		"PIPELEEK_AZURE_DEVOPS_SCAN_ARTIFACTS",
	}
	for _, key := range devopsScanKeys {
		if !strings.Contains(content, key) {
			t.Errorf("Expected config to contain env var reference %q", key)
		}
	}

	// circle scan keys
	circleScanKeys := []string{
		"PIPELEEK_CIRCLE_SCAN_VCS",
		"PIPELEEK_CIRCLE_SCAN_MAX_PIPELINES",
	}
	for _, key := range circleScanKeys {
		if !strings.Contains(content, key) {
			t.Errorf("Expected config to contain env var reference %q", key)
		}
	}
}
