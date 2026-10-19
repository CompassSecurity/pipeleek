package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinRules(t *testing.T) {
	builtins := BuiltinPatterns()
	require.Len(t, builtins, 15)
	assert.Equal(t, "medium", builtins[0].Pattern.Pattern.Confidence)
	for _, assignment := range []string{
		"GITLAB_USER_ID=12345", "KUBECONFIG=/tmp/config", "CI_SERVER_TLS_KEY_FILE=/tmp/key",
		"CI_REPOSITORY_URL=https://example.test/repo", "CI_REGISTRY_PASSWORD=secret",
		"DOCKER_AUTH_CONFIG={}", "CI_REGISTRY_PASSWORD=", "CI_REGISTRY_PASSWORD=****",
	} {
		t.Run(assignment, func(t *testing.T) {
			require.Len(t, builtins[0].FindAllIndex([]byte(assignment)), 1)
		})
	}
	for _, pattern := range builtins[1:] {
		require.Equal(t, "high", pattern.Pattern.Pattern.Confidence)
		var token string
		switch pattern.Pattern.Pattern.Name {
		case "Gitlab - Personal Access Token v2":
			token = "glpat-" + strings.Repeat("a", 20)
		case "Gitlab - Personal Access Token v3":
			token = "glpat-" + strings.Repeat("a", 27) + ".ab.123456789"
		default:
			token = strings.Split(pattern.Pattern.Pattern.Regex, "[")[0] + strings.Repeat("a", 20)
		}
		t.Run(pattern.Pattern.Pattern.Name, func(t *testing.T) {
			data := []byte("token='" + token + "'")
			hits := pattern.FindAllIndex(data)
			require.Len(t, hits, 1)
			assert.Equal(t, token, string(data[hits[0][0]:hits[0][1]]))
		})
	}
	for _, text := range []string{"ordinary text", "arn:aws:iam::123456789012:role/test", "s3://bucket/path", "https://example.test", "/tmp/config"} {
		for _, pattern := range builtins {
			assert.Empty(t, pattern.FindAllIndex([]byte(text)), "%s on %q", pattern.Pattern.Pattern.Name, text)
		}
	}
}

func TestPATBoundaries(t *testing.T) {
	v2, v3 := BuiltinPatterns()[1], BuiltinPatterns()[2]
	pat := "glpat-" + strings.Repeat("a", 20)
	for _, text := range []string{pat, "TOKEN=" + pat, "(" + pat + ")", pat + ".", pat + ",", " " + pat + " " + pat} {
		assert.NotEmpty(t, v2.FindAllIndex([]byte(text)), text)
	}
	for _, text := range []string{
		"glpat-" + strings.Repeat("a", 19), "glpat-" + strings.Repeat("a", 23),
		"x" + pat, pat + ".ab.123456789",
		"glpat-" + strings.Repeat("a", 27) + "XabX123456789",
	} {
		assert.Empty(t, v2.FindAllIndex([]byte(text)), text)
		assert.Empty(t, v3.FindAllIndex([]byte(text)), text)
	}
	for _, length := range []int{27, 100, 300} {
		pat3 := "glpat-" + strings.Repeat("a", length) + ".ab.123456789"
		assert.Empty(t, v2.FindAllIndex([]byte(pat3)))
		hits := v3.FindAllIndex([]byte(pat3))
		require.Len(t, hits, 1)
		assert.Equal(t, []int{0, len(pat3)}, hits[0])
		assert.Empty(t, v3.FindAllIndex([]byte(pat3+"x")))
	}
}

func TestLoadRulesMissingFile(t *testing.T) {
	dir := t.TempDir()
	patterns, err := loadRules(filepath.Join(dir, ruleFileName))
	require.NoError(t, err)
	assert.Len(t, patterns, 15)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "Loading embedded defaults must not write or download files")
}

func TestLoadRulesCustomOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), ruleFileName)
	data := []byte(`patterns:
  - pattern:
      name: Gitlab - Predefined Environment Variable
      regex: CUSTOM_ONLY
      confidence: custom-confidence
  - pattern:
      name: Additional
      regex: EXTRA
      confidence: high
`)
	require.NoError(t, os.WriteFile(path, data, 0600))
	patterns, err := loadRules(path)
	require.NoError(t, err)
	require.Len(t, patterns, 16)
	assert.Equal(t, "custom-confidence", patterns[0].Pattern.Pattern.Confidence)
	assert.Empty(t, patterns[0].FindAllIndex([]byte("GITLAB_USER_ID=1")))
	assert.Len(t, patterns[0].FindAllIndex([]byte("CUSTOM_ONLY")), 1)
	assert.Len(t, patterns[15].FindAllIndex([]byte("EXTRA")), 1)
	unchanged, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, data, unchanged)
	appended := AppendPipeleekRules([]types.PatternElement{patterns[0].Pattern})
	assert.Len(t, appended, 15)
	assert.Equal(t, patterns[0].Pattern, appended[0])
}

func TestInvalidLocalRules(t *testing.T) {
	for _, test := range []struct {
		name, yaml, errorText string
	}{
		{"YAML", "patterns: [", "invalid YAML"},
		{"regex", "patterns:\n- pattern: {name: Bad, regex: '[', confidence: high}", `rule "Bad": invalid regex`},
		{"missing name", "patterns:\n- pattern: {regex: ok, confidence: high}", "requires"},
		{"missing regex", "patterns:\n- pattern: {name: Bad, confidence: high}", "requires"},
		{"missing confidence", "patterns:\n- pattern: {name: Bad, regex: ok}", "requires"},
		{"duplicates", "patterns:\n- pattern: {name: Bad, regex: ok, confidence: high}\n- pattern: {name: Bad, regex: other, confidence: low}", `duplicate rule name "Bad"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ruleFileName)
			require.NoError(t, os.WriteFile(path, []byte(test.yaml), 0600))
			_, err := loadRules(path)
			require.ErrorContains(t, err, test.errorText)
			assert.ErrorContains(t, err, path)
		})
	}
	_, err := loadRules(t.TempDir())
	require.ErrorContains(t, err, "opening")
}

func TestInitRulesRepeatedFilters(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Cleanup(func() {
		state.Lock()
		state.patterns, state.detectors, state.filter = nil, nil, nil
		state.Unlock()
	})
	for _, filter := range [][]string{{"high"}, {"medium"}, {"verified"}, {}} {
		InitRules(filter)
		assert.Len(t, GetSecretsPatterns().Patterns, 15, "Filtering is performed on final findings, not cached definitions")
		assert.NotEmpty(t, GetTruffleHogRules())
		assert.Equal(t, filter, GetConfidenceFilter())
	}
	filter := GetConfidenceFilter()
	filter = append(filter, "changed")
	assert.Empty(t, GetConfidenceFilter())
	assert.Equal(t, []string{"changed"}, filter)
	assert.Len(t, AppendPipeleekRules(nil), 15)
	require.NoError(t, os.WriteFile(ruleFileName, []byte("patterns:\n- pattern: {name: Reloaded, regex: RELOADED, confidence: custom}\n"), 0600))
	InitRules([]string{"custom"})
	assert.Len(t, GetCompiledPatterns(), 16)
	assert.Equal(t, "Reloaded", GetSecretsPatterns().Patterns[15].Pattern.Name)
	require.NoError(t, os.WriteFile(ruleFileName, []byte("patterns: []\n"), 0600))
	InitRules(nil)
	assert.Len(t, GetCompiledPatterns(), 15)
}
