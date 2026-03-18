package rules

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppendPipeleekRules(t *testing.T) {
	tests := []struct {
		name          string
		inputRules    []types.PatternElement
		expectedCount int
	}{
		{
			name:          "empty rules",
			inputRules:    []types.PatternElement{},
			expectedCount: 13,
		},
		{
			name: "with existing rules",
			inputRules: []types.PatternElement{
				{Pattern: types.PatternPattern{Name: "Test Rule", Regex: "test", Confidence: "high"}},
			},
			expectedCount: 14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AppendPipeleekRules(tt.inputRules)
			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d rules, got %d", tt.expectedCount, len(result))
			}

			found := false
			for _, rule := range result {
				if rule.Pattern.Name == "Gitlab - Predefined Environment Variable" {
					found = true
					if rule.Pattern.Confidence != "medium" {
						t.Errorf("Expected confidence 'medium', got %q", rule.Pattern.Confidence)
					}
					break
				}
			}
			if !found {
				t.Error("Custom GitLab rule not found in appended rules")
			}
		})
	}
}

func TestGetSecretsPatterns(t *testing.T) {
	patterns := GetSecretsPatterns()
	t.Logf("Patterns count: %d", len(patterns.Patterns))
}

func TestGetTruffleHogRules(t *testing.T) {
	rules := GetTruffleHogRules()
	t.Logf("TruffleHog rules count: %d", len(rules))
}

func TestDownloadRules(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(origWd)
	}()

	_ = os.Chdir(tmpDir)

	t.Run("rules file does not exist", func(t *testing.T) {
		if _, err := os.Stat(ruleFileName); err == nil {
			_ = os.Remove(ruleFileName)
		}

		DownloadRules()

		if _, err := os.Stat(ruleFileName); os.IsNotExist(err) {
			t.Error("Expected rules file to be downloaded")
		}
	})

	t.Run("rules file already exists", func(t *testing.T) {
		if _, err := os.Stat(ruleFileName); os.IsNotExist(err) {
			_ = os.WriteFile(ruleFileName, []byte("dummy"), 0644)
		}

		DownloadRules()

		if _, err := os.Stat(ruleFileName); os.IsNotExist(err) {
			t.Error("Expected rules file to exist")
		}
	})
}

func TestInitRules(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(origWd)
		secretsPatterns = types.SecretsPatterns{}
		truffelhogRules = nil
	}()

	_ = os.Chdir(tmpDir)

	// Create a minimal valid rules file
	rulesYAML := `patterns:
  - pattern:
      name: Test Pattern
      regex: "test"
      confidence: high
  - pattern:
      name: Medium Pattern
      regex: "medium"
      confidence: medium
  - pattern:
      name: Low Pattern
      regex: "low"
      confidence: low
`
	_ = os.WriteFile(ruleFileName, []byte(rulesYAML), 0644)

	t.Run("no filter", func(t *testing.T) {
		secretsPatterns = types.SecretsPatterns{}
		truffelhogRules = nil

		InitRules([]string{})

		if len(secretsPatterns.Patterns) == 0 {
			t.Error("Expected patterns to be loaded")
		}

		if len(truffelhogRules) == 0 {
			t.Error("Expected TruffleHog rules to be loaded")
		}

		// Should include custom GitLab rule
		found := false
		for _, p := range secretsPatterns.Patterns {
			if p.Pattern.Name == "Gitlab - Predefined Environment Variable" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected custom GitLab rule to be appended")
		}
	})

	t.Run("with confidence filter high", func(t *testing.T) {
		secretsPatterns = types.SecretsPatterns{}
		truffelhogRules = nil

		InitRules([]string{"high"})

		// Should only have high confidence patterns
		for _, p := range secretsPatterns.Patterns {
			if p.Pattern.Confidence != "high" {
				t.Errorf("Expected only high confidence patterns, got %q", p.Pattern.Confidence)
			}
		}
	})

	t.Run("with multiple confidence filters", func(t *testing.T) {
		secretsPatterns = types.SecretsPatterns{}
		truffelhogRules = nil

		InitRules([]string{"high", "medium"})

		// Should have high and medium confidence patterns
		for _, p := range secretsPatterns.Patterns {
			if p.Pattern.Confidence != "high" && p.Pattern.Confidence != "medium" {
				t.Errorf("Expected only high/medium confidence patterns, got %q", p.Pattern.Confidence)
			}
		}
	})

	t.Run("filter removes all rules", func(t *testing.T) {
		secretsPatterns = types.SecretsPatterns{}
		truffelhogRules = nil

		InitRules([]string{"nonexistent"})

		// Should have zero patterns after filtering
		if len(secretsPatterns.Patterns) != 0 {
			t.Errorf("Expected 0 patterns after filtering, got %d", len(secretsPatterns.Patterns))
		}
	})

	t.Run("already initialized", func(t *testing.T) {
		// First initialize patterns
		secretsPatterns = types.SecretsPatterns{}
		truffelhogRules = nil
		InitRules([]string{})
		initialCount := len(secretsPatterns.Patterns)

		if initialCount == 0 {
			t.Error("Expected patterns to be initialized")
		}

		// Call InitRules again - should not reload since patterns exist
		InitRules([]string{})

		// Should not have changed
		if len(secretsPatterns.Patterns) != initialCount {
			t.Errorf("Expected patterns count %d to remain unchanged, got %d", initialCount, len(secretsPatterns.Patterns))
		}
	})
}

func TestGetSecretsPatterns_AfterInit(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(origWd)
		secretsPatterns = types.SecretsPatterns{}
	}()

	_ = os.Chdir(tmpDir)

	rulesYAML := `patterns:
  - pattern:
      name: Test Pattern
      regex: "test"
      confidence: high
`
	_ = os.WriteFile(ruleFileName, []byte(rulesYAML), 0644)

	secretsPatterns = types.SecretsPatterns{}
	InitRules([]string{})

	patterns := GetSecretsPatterns()

	if len(patterns.Patterns) == 0 {
		t.Error("Expected non-empty patterns")
	}
}

func TestGetTruffleHogRules_AfterInit(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(origWd)
		secretsPatterns = types.SecretsPatterns{}
		truffelhogRules = nil
	}()

	_ = os.Chdir(tmpDir)

	rulesYAML := `patterns:
  - pattern:
      name: Test Pattern
      regex: "test"
      confidence: high
`
	_ = os.WriteFile(ruleFileName, []byte(rulesYAML), 0644)

	secretsPatterns = types.SecretsPatterns{}
	truffelhogRules = nil
	InitRules([]string{})

	rules := GetTruffleHogRules()

	if len(rules) == 0 {
		t.Error("Expected non-empty TruffleHog rules")
	}
}

func TestDownloadFile_Success(t *testing.T) {
	content := "rules file content from mock"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	destFile := filepath.Join(tmpDir, "rules.yml")

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	err := downloadFile(srv.URL, destFile, client)
	require.NoError(t, err)

	data, err := os.ReadFile(destFile)
	require.NoError(t, err)
	assert.Equal(t, content, string(data))
}

func TestDownloadFile_HTTPError(t *testing.T) {
	tmpDir := t.TempDir()
	destFile := filepath.Join(tmpDir, "rules.yml")

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	client.RetryMax = 0

	err := downloadFile("http://127.0.0.1:0", destFile, client)
	assert.Error(t, err)
}

func TestDownloadFile_BadOutputPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data"))
	}))
	defer srv.Close()

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	// Attempting to write to a path inside a non-existent directory should fail
	err := downloadFile(srv.URL, "/nonexistent-dir/rules.yml", client)
	assert.Error(t, err)
}

func TestAppendPipeleekRules_GitLabTokenRules(t *testing.T) {
	result := AppendPipeleekRules([]types.PatternElement{})

	expectedTokenRules := []string{
		"Gitlab - Personal Access Token",
		"Gitlab - Pipeline Trigger Token",
		"Gitlab - Runner Registration Token",
		"Gitlab - Deploy Token",
		"Gitlab - CI Build Token",
		"Gitlab - OAuth Application Secret",
		"Gitlab - SCIM/OAuth Access Token",
		"Gitlab - Feed Token",
		"Gitlab - Incoming Mail Token",
		"Gitlab - Feature Flags Client Token",
		"Gitlab - Agent for Kubernetes Token",
		"Gitlab - Runner Authentication Token (Legacy)",
	}

	for _, expectedName := range expectedTokenRules {
		found := false
		for _, rule := range result {
			if rule.Pattern.Name == expectedName {
				found = true
				assert.Equal(t, "high", rule.Pattern.Confidence, "GitLab token rule %q should have high confidence", expectedName)
				break
			}
		}
		assert.True(t, found, "Expected GitLab token rule %q to be present", expectedName)
	}
}
