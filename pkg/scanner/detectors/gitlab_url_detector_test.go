package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewGitLabURLDetector(t *testing.T) {
	detector, err := NewGitLabURLDetector()
	assert.NoError(t, err)
	assert.NotNil(t, detector)
	assert.Len(t, detector.patterns, 14, "Should have 14 GitLab token patterns")
}

func TestNewGitLabURLDetector_VerificationStrategies(t *testing.T) {
	detector, err := NewGitLabURLDetector()
	assert.NoError(t, err)

	strategies := map[string]verificationStrategy{}
	for _, pattern := range detector.patterns {
		strategies[pattern.name] = pattern.strategy
	}

	assert.Equal(t, verifyUserAPI, strategies["Gitlab - Personal Access Token v2"])
	assert.Equal(t, verifyUserAPI, strategies["Gitlab - Personal Access Token v3"])
	assert.Equal(t, verifyUserAPI, strategies["Gitlab - SCIM/OAuth Access Token"])
	assert.Equal(t, verifyRunnerAPI, strategies["Gitlab - Runner Authentication Token"])
	assert.Equal(t, verifyRunnerAPI, strategies["Gitlab - Runner Token (Legacy)"])
	assert.Equal(t, verifyNone, strategies["Gitlab - Runner Registration Token"])
	assert.Equal(t, verifyNone, strategies["Gitlab - Pipeline Trigger Token"])
}

func TestGitLabURLDetector_Keywords(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	keywords := detector.Keywords()

	assert.Contains(t, keywords, "glpat-")
	assert.Contains(t, keywords, "glptt-")
	assert.Contains(t, keywords, "gldt-")
	assert.Contains(t, keywords, "glrt-")
	assert.Contains(t, keywords, "glrtr-")
	assert.Contains(t, keywords, "glcbt-")
	assert.Contains(t, keywords, "gloas-")
	assert.Contains(t, keywords, "glsoat-")
	assert.Contains(t, keywords, "glft-")
	assert.Contains(t, keywords, "glimt-")
	assert.Contains(t, keywords, "glffct-")
	assert.Contains(t, keywords, "glagent-")
	assert.Contains(t, keywords, "GR1348941")
}

func TestGitLabURLDetector_Type(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	assert.NotNil(t, detector.Type())
}

func TestGitLabURLDetector_Description(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	desc := detector.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "GitLab")
}

func TestGitLabURLDetector_FromData_PersonalAccessTokenV2(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	ctx := context.Background()

	// Test data containing a v2 PAT pattern (format: glpat-[20-22 chars])
	testData := []byte(`
	export GITLAB_TOKEN="glpat-abcdefghijklmnopqrst"
	echo "token is: glpat-1234567890123456789012"
	`)

	results, err := detector.FromData(ctx, false, testData)
	assert.NoError(t, err)
	// Should find 2 matches without verification
	assert.GreaterOrEqual(t, len(results), 1)

	// Verify detected tokens
	for _, result := range results {
		assert.Equal(t, "Gitlab - Personal Access Token v2", result.DetectorName)
		assert.False(t, result.Verified) // Without verification, should be false
		assert.NotEmpty(t, result.Raw)
	}
}

func TestGitLabURLDetector_FromData_PipelineTriggerToken(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	ctx := context.Background()

	testData := []byte(`pipeline_token: glptt-abcdefghijklmnopqrstuvwxy`)

	results, err := detector.FromData(ctx, false, testData)
	assert.NoError(t, err)
	assert.Greater(t, len(results), 0)

	found := false
	for _, result := range results {
		if result.DetectorName == "Gitlab - Pipeline Trigger Token" {
			found = true
			assert.False(t, result.Verified)
		}
	}
	assert.True(t, found)
}

func TestGitLabURLDetector_FromData_RunnerRegistrationToken(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	ctx := context.Background()

	testData := []byte(`runner_token: glrtr-1234567890123456789012`)

	results, err := detector.FromData(ctx, false, testData)
	assert.NoError(t, err)
	assert.Greater(t, len(results), 0)

	found := false
	for _, result := range results {
		if result.DetectorName == "Gitlab - Runner Registration Token" {
			found = true
		}
	}
	assert.True(t, found)
}

func TestGitLabURLDetector_FromData_DeployToken(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	ctx := context.Background()

	testData := []byte(`deploy_token: gldt-abcdefghijklmnopqrst`)

	results, err := detector.FromData(ctx, false, testData)
	assert.NoError(t, err)
	assert.Greater(t, len(results), 0)

	found := false
	for _, result := range results {
		if result.DetectorName == "Gitlab - Deploy Token" {
			found = true
		}
	}
	assert.True(t, found)
}

func TestGitLabURLDetector_FromData_VerifyDisabledNoURL(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	ClearGitLabURL()
	ctx := context.Background()

	testData := []byte(`token: glpat-abcdefghijklmnopqrst`)

	results, err := detector.FromData(ctx, false, testData)
	assert.NoError(t, err)
	assert.Greater(t, len(results), 0)
	found := false
	for _, result := range results {
		if result.DetectorName == "Gitlab - Personal Access Token v2" {
			found = true
			assert.False(t, result.Verified)
		}
	}
	assert.True(t, found)
}

func TestGitLabURLDetector_FromData_VerifyEnabledNoURL(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	ClearGitLabURL()
	ctx := context.Background()

	testData := []byte(`token: glpat-abcdefghijklmnopqrst`)

	// With verification enabled but no URL set, should still detect but not verify
	results, err := detector.FromData(ctx, true, testData)
	assert.NoError(t, err)
	// Should detect the token pattern but not verify it (URL is empty)
	assert.Equal(t, 1, len(results))
	assert.False(t, results[0].Verified)
}

func TestSetGetClearGitLabURL(t *testing.T) {
	// Clear first
	ClearGitLabURL()
	assert.Equal(t, "", GetGitLabURL())

	// Set
	testURL := "https://gitlab.example.com"
	SetGitLabURL(testURL)
	assert.Equal(t, testURL, GetGitLabURL())

	// Clear again
	ClearGitLabURL()
	assert.Equal(t, "", GetGitLabURL())
}

func TestGitLabURLDetector_MultipleTokenTypes(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	ctx := context.Background()

	testData := []byte(`
	pat: glpat-abcdefghijklmnopqrst
	trigger: glptt-1234567890123456789012
	runner: glrt-abcdefghijklmnopqrst
	deploy: gldt-1234567890123456789012
	`)

	results, err := detector.FromData(ctx, false, testData)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 4)

	// Check that we have different detector names for different token types
	detectorNames := make(map[string]bool)
	for _, result := range results {
		detectorNames[result.DetectorName] = true
	}
	assert.Greater(t, len(detectorNames), 1, "Should detect multiple token types")
}

func TestGitLabURLDetector_LegacyRunnerToken(t *testing.T) {
	detector, _ := NewGitLabURLDetector()
	ctx := context.Background()

	testData := []byte(`legacy_runner_token: GR1348941abcdefghijklmnopqrst`)

	results, err := detector.FromData(ctx, false, testData)
	assert.NoError(t, err)
	assert.Greater(t, len(results), 0)

	found := false
	for _, result := range results {
		if result.DetectorName == "Gitlab - Runner Token (Legacy)" {
			found = true
		}
	}
	assert.True(t, found)
}
