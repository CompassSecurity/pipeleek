package gen_test

import (
	"strings"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config/gen"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func testRootCommand() *cobra.Command {
	root := &cobra.Command{Use: "pipeleek"}

	gl := &cobra.Command{Use: "gl [command]"}
	var gitlabURL string
	var gitlabToken string
	gl.PersistentFlags().StringVarP(&gitlabURL, "gitlab", "g", "https://gitlab.example.com", "GitLab instance URL")
	gl.PersistentFlags().StringVarP(&gitlabToken, "token", "t", "", "GitLab API token")

	scan := &cobra.Command{Use: "scan"}
	var search string
	var artifacts bool
	var threads int
	var maxArtifactSize string
	var confidence []string
	var hitTimeout string
	scan.Flags().StringVarP(&search, "search", "s", "", "Search query")
	scan.Flags().BoolVarP(&artifacts, "artifacts", "a", false, "Scan artifacts")
	scan.Flags().IntVarP(&threads, "threads", "", 4, "Threads")
	scan.Flags().StringVarP(&maxArtifactSize, "max-artifact-size", "", "500Mb", "Max artifact size")
	scan.Flags().StringSliceVarP(&confidence, "confidence", "", []string{}, "Confidence filter")
	scan.Flags().StringVarP(&hitTimeout, "hit-timeout", "", "60s", "Per-hit timeout")
	gl.AddCommand(scan)

	gh := &cobra.Command{Use: "gh [command]"}
	var githubURL string
	gh.PersistentFlags().StringVarP(&githubURL, "github", "g", "https://api.github.com", "GitHub API URL")
	ghScan := &cobra.Command{Use: "scan"}
	var org string
	ghScan.Flags().StringVarP(&org, "org", "", "", "Organization")
	gh.AddCommand(ghScan)

	root.AddCommand(gl)
	root.AddCommand(gh)

	return root
}

func TestGenerateExampleConfig_IsValidYAML(t *testing.T) {
	content := gen.GenerateExampleConfig(testRootCommand())
	if content == "" {
		t.Fatal("GenerateExampleConfig returned empty string")
	}

	lines := strings.Split(content, "\n")
	var yamlLines []string
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		yamlLines = append(yamlLines, line)
	}
	yamlContent := strings.Join(yamlLines, "\n")

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &parsed); err != nil {
		t.Errorf("GenerateExampleConfig output is not valid YAML: %v", err)
	}
}

func TestGenerateExampleConfig_ContainsExpectedSections(t *testing.T) {
	content := gen.GenerateExampleConfig(testRootCommand())

	required := []string{
		"common:",
		"gitlab:",
		"github:",
		"scan:",
	}
	for _, key := range required {
		if !strings.Contains(content, key) {
			t.Errorf("Expected generated config to contain %q", key)
		}
	}
}

func TestGenerateExampleConfig_ContainsDynamicEnvVars(t *testing.T) {
	content := gen.GenerateExampleConfig(testRootCommand())

	requiredEnvVars := []string{
		"PIPELEEK_COMMON_THREADS",
		"PIPELEEK_COMMON_MAX_ARTIFACT_SIZE",
		"PIPELEEK_GITLAB_GITLAB",
		"PIPELEEK_GITLAB_SCAN_SEARCH",
		"PIPELEEK_GITHUB_GITHUB",
		"PIPELEEK_GITHUB_SCAN_ORG",
	}

	for _, envVar := range requiredEnvVars {
		if !strings.Contains(content, envVar) {
			t.Errorf("Expected generated config to contain env var reference %q", envVar)
		}
	}
}

func TestGenerateExampleConfig_CorrectCommonDefaultTypes(t *testing.T) {
	content := gen.GenerateExampleConfig(testRootCommand())

	if !strings.Contains(content, `max_artifact_size: "500Mb"`) {
		t.Error("Expected max_artifact_size to be quoted string \"500Mb\"")
	}
	if !strings.Contains(content, `hit_timeout: "60s"`) {
		t.Error("Expected hit_timeout to be quoted string \"60s\"")
	}
	if !strings.Contains(content, "confidence: []") {
		t.Error("Expected confidence to be represented as an empty list []")
	}
}

func TestGenerateExampleConfig_IsDeterministic(t *testing.T) {
	first := gen.GenerateExampleConfig(testRootCommand())
	second := gen.GenerateExampleConfig(testRootCommand())

	if first != second {
		t.Fatal("GenerateExampleConfig output must be deterministic across runs")
	}
}
