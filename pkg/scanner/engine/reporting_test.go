package engine

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/scanner/rules"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	trdetectors "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type fixtureDetector struct {
	results []trdetectors.Result
	err     error
	verify  bool
}

func (d *fixtureDetector) FromData(_ context.Context, verify bool, _ []byte) ([]trdetectors.Result, error) {
	d.verify = verify
	return d.results, d.err
}

func (*fixtureDetector) Keywords() []string { return []string{"fixture"} }
func (*fixtureDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Gitlab
}
func (*fixtureDetector) Description() string { return "Test fixture" }

func TestTruffleHogReportingRespectsVerification(t *testing.T) {
	inconclusive := trdetectors.Result{DetectorType: detector_typepb.DetectorType_Gitlab, Raw: []byte("inconclusive")}
	inconclusive.SetVerificationError(errors.New("verification failed"))
	for _, verify := range []bool{true, false} {
		detector := &fixtureDetector{results: []trdetectors.Result{
			{DetectorType: detector_typepb.DetectorType_Gitlab, Raw: []byte("identifier"), RawV2: []byte("complete-credential"), Verified: true},
			{DetectorType: detector_typepb.DetectorType_Gitlab, Raw: []byte("candidate")},
			inconclusive,
		}}
		findings := detectTruffleHog(context.Background(), detector, verify, []byte("fixture"))
		expected := 3
		if verify {
			expected = 1
		}
		require.Len(t, findings, expected)
		assert.Equal(t, verify, detector.verify)
		assert.Equal(t, "complete-credential", findings[0].Text)
		assert.Equal(t, "verified", findings[0].Pattern.Pattern.Confidence)
		if !verify {
			assert.Equal(t, "candidate", findings[1].Text)
			assert.Equal(t, "trufflehog", findings[1].Pattern.Pattern.Confidence)
			assert.Equal(t, "trufflehog", findings[2].Pattern.Pattern.Confidence)
		}
		for _, finding := range findings {
			assert.Equal(t, EngineTruffleHog, finding.Engine)
			assert.Equal(t, "Gitlab", finding.Pattern.Pattern.Name)
		}
	}
}

func TestTruffleHogPreservesPartialResultsWithoutLeakingErrors(t *testing.T) {
	var output bytes.Buffer
	original := log.Logger
	log.Logger = zerolog.New(&output)
	t.Cleanup(func() { log.Logger = original })
	result := trdetectors.Result{DetectorType: detector_typepb.DetectorType_Gitlab, Raw: []byte("candidate")}
	result.SetVerificationError(errors.New("verification failed for sensitive-fixture"), "sensitive-fixture")
	detector := &fixtureDetector{
		results: []trdetectors.Result{
			result,
			{DetectorType: detector_typepb.DetectorType_Gitlab, Raw: []byte("verified-candidate"), Verified: true},
		},
		err:     errors.New("detector error containing sensitive-fixture"),
	}
	findings := detectTruffleHog(context.Background(), detector, true, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "verified", findings[0].Pattern.Pattern.Confidence)
	assert.Equal(t, "verified-candidate", findings[0].Text)
	assert.Contains(t, output.String(), "TruffleHog detector failed")
	assert.NotContains(t, output.String(), "verification was inconclusive")
	assert.NotContains(t, output.String(), "sensitive-fixture")

	output.Reset()
	detector.err = nil
	detector.results = []trdetectors.Result{result}
	findings = detectTruffleHog(context.Background(), detector, true, nil)
	assert.Empty(t, findings)
	assert.Empty(t, output.String(), "Verification errors alone must not emit diagnostic logs")

	findings = detectTruffleHog(context.Background(), detector, false, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "trufflehog", findings[0].Pattern.Pattern.Confidence)
	assert.Empty(t, output.String(), "Verification errors alone must not emit diagnostic logs")
}

func TestConfidenceFilteringAcrossEngines(t *testing.T) {
	var findings []types.Finding
	for _, engine := range []string{EngineRules, EngineBetterleaks, EngineGitLab, EngineTruffleHog} {
		for _, confidence := range []string{"verified", "trufflehog", "high", "medium", "low", "custom-confidence"} {
			findings = append(findings, types.Finding{
				Engine:  engine,
				Pattern: types.PatternElement{Pattern: types.PatternPattern{Confidence: confidence}},
			})
		}
	}
	for _, filter := range [][]string{nil, {"verified"}, {"trufflehog"}, {"high", "medium"}, {"custom-confidence"}, {"nonexistent"}} {
		filtered := filterFindings(slices.Clone(findings), filter)
		expected := 24
		if len(filter) > 0 {
			expected = 4 * len(filter)
		}
		if slices.Contains(filter, "nonexistent") {
			expected = 0
		}
		require.Len(t, filtered, expected)
		for _, finding := range filtered {
			if len(filter) > 0 {
				assert.Contains(t, filter, finding.Pattern.Pattern.Confidence)
			}
		}
	}
}

func TestDetectHitsConfidenceSelectionBeforeDeduplication(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Cleanup(func() { rules.InitRules(nil) })
	deduplicationMutex.Lock()
	previous := findingsDeduplicationList
	findingsDeduplicationList = nil
	deduplicationMutex.Unlock()
	t.Cleanup(func() {
		deduplicationMutex.Lock()
		findingsDeduplicationList = previous
		deduplicationMutex.Unlock()
	})

	rules.InitRules([]string{"verified"})
	findings, err := DetectHits([]byte("GITLAB_USER_ID=19357"), 1, false, time.Minute)
	require.NoError(t, err)
	assert.Empty(t, findings)

	rules.InitRules([]string{"medium"})
	findings, err = DetectHits([]byte("GITLAB_USER_ID=19357"), 1, false, time.Minute)
	require.NoError(t, err)
	require.Len(t, findings, 1, "An excluded result must not enter the deduplication state")
	assert.Equal(t, EngineRules, findings[0].Engine)
	assert.Equal(t, "medium", findings[0].Pattern.Pattern.Confidence)
}
