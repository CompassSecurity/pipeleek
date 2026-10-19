package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindingTypeAlias(t *testing.T) {
	// Test that type aliases work correctly
	finding := Finding{
		Pattern: PatternElement{
			Pattern: PatternPattern{
				Name:       "Test Pattern",
				Regex:      "test.*",
				Confidence: "high",
			},
		},
		Text: "test secret",
	}

	assert.Equal(t, "Test Pattern", finding.Pattern.Pattern.Name)
	assert.Equal(t, "test.*", finding.Pattern.Pattern.Regex)
	assert.Equal(t, "high", finding.Pattern.Pattern.Confidence)
	assert.Equal(t, "test secret", finding.Text)
}

func TestPatternElementTypeAlias(t *testing.T) {
	pattern := PatternElement{
		Pattern: PatternPattern{
			Name:       "AWS Key",
			Regex:      "AKIA[0-9A-Z]{16}",
			Confidence: "high",
		},
	}

	assert.Equal(t, "AWS Key", pattern.Pattern.Name)
	assert.Equal(t, "AKIA[0-9A-Z]{16}", pattern.Pattern.Regex)
}

func TestSecretsPatternsTypeAlias(t *testing.T) {
	patterns := SecretsPatterns{
		Patterns: []PatternElement{
			{
				Pattern: PatternPattern{
					Name:       "Pattern 1",
					Regex:      "regex1",
					Confidence: "high",
				},
			},
			{
				Pattern: PatternPattern{
					Name:       "Pattern 2",
					Regex:      "regex2",
					Confidence: "medium",
				},
			},
		},
	}

	assert.Len(t, patterns.Patterns, 2)
	assert.Equal(t, "Pattern 1", patterns.Patterns[0].Pattern.Name)
	assert.Equal(t, "Pattern 2", patterns.Patterns[1].Pattern.Name)
}

func TestDetectionResultTypeAlias(t *testing.T) {
	tests := []struct {
		name        string
		result      DetectionResult
		expectError bool
	}{
		{
			name: "successful detection with findings",
			result: DetectionResult{
				Findings: []Finding{
					{
						Pattern: PatternElement{
							Pattern: PatternPattern{
								Name:       "Secret",
								Regex:      "secret.*",
								Confidence: "high",
							},
						},
						Text: "secret123",
					},
				},
				Error: nil,
			},
			expectError: false,
		},
		{
			name: "detection with no findings",
			result: DetectionResult{
				Findings: []Finding{},
				Error:    nil,
			},
			expectError: false,
		},
		{
			name: "detection with error",
			result: DetectionResult{
				Findings: nil,
				Error:    assert.AnError,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectError {
				assert.Error(t, tt.result.Error)
			} else {
				assert.NoError(t, tt.result.Error)
			}

			if !tt.expectError && len(tt.result.Findings) > 0 {
				assert.NotEmpty(t, tt.result.Findings[0].Text)
			}
		})
	}
}

// Test that exported function references work
func TestExportedFunctionReferences(t *testing.T) {
	// Verify that function aliases are not nil
	assert.NotNil(t, InitRules, "InitRules should be exported")
	assert.NotNil(t, AppendPipeleekRules, "AppendPipeleekRules should be exported")
	assert.NotNil(t, DetectHits, "DetectHits should be exported")
	assert.NotNil(t, DetectFileHits, "DetectFileHits should be exported")
	assert.NotNil(t, HandleArchiveArtifact, "HandleArchiveArtifact should be exported")
}
