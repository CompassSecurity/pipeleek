package engine

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/scanner/rules"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
	"github.com/acarl005/stripansi"
	"github.com/rs/zerolog/log"
	"github.com/rxwycdh/rxhash"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/wandb/parallel"
)

var findingsDeduplicationList []string
var deduplicationMutex sync.Mutex

func DetectHits(text []byte, maxThreads int, enableTruffleHogVerification bool, timeout time.Duration) ([]types.Finding, error) {
	result := make(chan types.DetectionResult, 1)
	go func() {
		result <- DetectHitsWithTimeout(text, maxThreads, enableTruffleHogVerification)
	}()
	select {
	case <-time.After(timeout):
		return nil, errors.New("hit detection timed out (" + timeout.String() + ")")
	case result := <-result:
		return result.Findings, result.Error
	}
}

func DetectHitsWithTimeout(text []byte, maxThreads int, enableTruffleHogVerification bool) types.DetectionResult {
	ctx := context.Background()
	group := parallel.Collect[[]types.Finding](parallel.Limited(ctx, maxThreads))

	secretsPatterns := rules.GetSecretsPatterns()

	for _, pattern := range secretsPatterns.Patterns {
		group.Go(func(ctx context.Context) ([]types.Finding, error) {
			findingsYml := []types.Finding{}
			m, err := regexp.Compile(pattern.Pattern.Regex)
			if err != nil {
				log.Trace().Err(err).Str("name", pattern.Pattern.Name).Str("regex", pattern.Pattern.Regex).Msg("Failed compiling regex expression")
				return findingsYml, nil
			}

			hits := m.FindAllIndex(text, -1)

			for _, hit := range hits {
				hitStr := extractHitWithSurroundingText(text, hit, 50)
				hitStr = cleanHitLine(hitStr)
				if len(hitStr) > 1024 {
					hitStr = hitStr[0:1024]
				}

				if hitStr != "" {
					findingsYml = append(findingsYml, types.Finding{Pattern: pattern, Text: hitStr})
				}
			}

			return findingsYml, nil
		})
	}

	resultsYml, err := group.Wait()
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed waiting for parallel hit detection")
	}

	findingsCombined := slices.Concat(resultsYml...)

	trGroup := parallel.Collect[[]types.Finding](parallel.Limited(ctx, maxThreads))
	for _, detector := range defaults.DefaultDetectors() {
		trGroup.Go(func(ctx context.Context) ([]types.Finding, error) {
			findingsTr := []types.Finding{}
			trHits, err := detector.FromData(ctx, enableTruffleHogVerification, text)
			if err != nil {
				log.Error().Msg("Truffelhog Detector Failed " + err.Error())
				return []types.Finding{}, err
			}

			for _, result := range trHits {
				secret := result.Raw
				if len(result.RawV2) > 0 {
					secret = result.RawV2
				}
				finding := types.Finding{Pattern: types.PatternElement{Pattern: types.PatternPattern{Name: result.DetectorType.String(), Confidence: "high-verified"}}, Text: string(secret)}

				if result.Verified {
					findingsTr = append(findingsTr, finding)
				}

				if !enableTruffleHogVerification {
					finding.Pattern.Pattern.Confidence = "trufflehog-unverified"
					findingsTr = append(findingsTr, finding)
				}
			}
			return findingsTr, nil
		})
	}

	resultsTr, err := trGroup.Wait()
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed waiting for trufflehog parallel hit detection")
	}

	findingsTr := slices.Concat(resultsTr...)
	totalFindings := slices.Concat(findingsCombined, findingsTr)
	return types.DetectionResult{Findings: deduplicateFindings(totalFindings), Error: nil}
}

func deduplicateFindings(totalFindings []types.Finding) []types.Finding {
	deduplicationMutex.Lock()
	defer deduplicationMutex.Unlock()
	var deduped []types.Finding
	deduped, findingsDeduplicationList = deduplicateFindingsWithState(totalFindings, findingsDeduplicationList)
	return deduped
}

// deduplicateFindingsWithState is a pure deduplication function that accepts and returns the seen-hash state.
// This enables testing without relying on the package-level global.
func deduplicateFindingsWithState(totalFindings []types.Finding, seenHashes []string) ([]types.Finding, []string) {
	dedupedFindings := []types.Finding{}
	for _, finding := range totalFindings {
		hash, _ := rxhash.HashStruct(finding)
		if !slices.Contains(seenHashes, hash) {
			dedupedFindings = append(dedupedFindings, finding)
			seenHashes = append(seenHashes, hash)
		}

		if len(seenHashes) > 500 {
			seenHashes = seenHashes[1:]
		}
	}
	return dedupedFindings, seenHashes
}

func extractHitWithSurroundingText(text []byte, hitIndex []int, additionalBytes int) string {
	startIndex := hitIndex[0]
	endIndex := hitIndex[1]

	extendedStartIndex := startIndex - additionalBytes
	if extendedStartIndex < 0 {
		startIndex = 0
	} else {
		startIndex = extendedStartIndex
	}

	extendedEndIndex := endIndex + additionalBytes
	if extendedEndIndex > len(text) {
		endIndex = len(text)
	} else {
		endIndex = extendedEndIndex
	}

	return string(text[startIndex:endIndex])
}

func cleanHitLine(text string) string {
	text = strings.ReplaceAll(text, "\n", " ")
	return stripansi.Strip(text)
}
