package engine

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/scanner/detectors"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/rules"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
	blanalyze "github.com/betterleaks/betterleaks/v2/analyze"
	blconfig "github.com/betterleaks/betterleaks/v2/config"
	blreport "github.com/betterleaks/betterleaks/v2/report"
	blscan "github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
)

// gitLabDotCom is the host hardcoded in Betterleaks' GitLab validators.
const gitLabDotCom = "https://gitlab.com"

// publicGitLabURL is where the stock GitLab rules validate; tests point it at a mock.
var publicGitLabURL = gitLabDotCom

const findingIndexAttr = "pipeleek.finding_index"

type betterleaksRuntimeKey struct {
	gitLabURL       string
	publicGitLabURL string
	verify          bool
	workers         int
	timeout         time.Duration
}

type betterleaksRuntime struct {
	scanner  *blscan.Scanner
	analyzer *blanalyze.Analyzer
	// selfHostedAnalyzer re-validates GitLab findings against the configured instance.
	selfHostedAnalyzer *blanalyze.Analyzer
	prefilter          sources.PrefilterFunc
}

var betterleaksRuntimes = struct {
	sync.Mutex
	items map[betterleaksRuntimeKey]*betterleaksRuntime
}{items: make(map[betterleaksRuntimeKey]*betterleaksRuntime)}

func getBetterleaksRuntime(gitLabURL string, verify bool, workers int, timeout time.Duration) (*betterleaksRuntime, error) {
	key := betterleaksRuntimeKey{
		gitLabURL:       strings.TrimRight(gitLabURL, "/"),
		publicGitLabURL: publicGitLabURL,
		verify:          verify,
		workers:         workers,
		timeout:         timeout,
	}

	betterleaksRuntimes.Lock()
	defer betterleaksRuntimes.Unlock()
	if runtime, ok := betterleaksRuntimes.items[key]; ok {
		return runtime, nil
	}

	config, err := blconfig.Default()
	if err != nil {
		return nil, err
	}
	rewriteGitLabRuleHosts(config, key.publicGitLabURL)

	scannerOptions := []blscan.Option{blscan.WithPrecompile(), blscan.WithWorkers(workers)}
	scanner, err := blscan.New(config, scannerOptions...)
	if err != nil {
		return nil, err
	}
	sourcePrefilter, err := prefilter.Compile(config.PrefilterExpr, prefilter.Options{})
	if err != nil {
		return nil, err
	}

	runtime := &betterleaksRuntime{scanner: scanner, prefilter: sourcePrefilter}
	if verify {
		analyzerOptions := []blanalyze.Option{
			blanalyze.WithPrecompile(),
			blanalyze.WithWorkers(workers),
			blanalyze.WithMaxRequestsPerTarget(100),
			blanalyze.WithRequestsPerSecond(10),
		}
		if timeout > 0 {
			analyzerOptions = append(analyzerOptions, blanalyze.WithTimeout(timeout))
		}
		runtime.analyzer, err = blanalyze.New(config, analyzerOptions...)
		if err != nil {
			return nil, err
		}

		if key.gitLabURL != "" && key.gitLabURL != key.publicGitLabURL {
			selfHostedConfig, err := blconfig.Default()
			if err != nil {
				return nil, err
			}
			rewriteGitLabRuleHosts(selfHostedConfig, key.gitLabURL)
			runtime.selfHostedAnalyzer, err = blanalyze.New(selfHostedConfig, analyzerOptions...)
			if err != nil {
				return nil, err
			}
		}
	}

	betterleaksRuntimes.items[key] = runtime
	return runtime, nil
}

func rewriteGitLabRuleHosts(config *blconfig.Config, gitLabURL string) {
	if gitLabURL == "" || gitLabURL == gitLabDotCom {
		return
	}
	for i := range config.Rules {
		if !isGitLabRule(config.Rules[i].ID) {
			continue
		}
		config.Rules[i].ValidateExpr = strings.ReplaceAll(config.Rules[i].ValidateExpr, gitLabDotCom, gitLabURL)
		config.Rules[i].AnalyzeExpr = strings.ReplaceAll(config.Rules[i].AnalyzeExpr, gitLabDotCom, gitLabURL)
	}
}

func isGitLabRule(ruleID string) bool {
	return strings.HasPrefix(ruleID, "gitlab-")
}

// mergeValidation keeps the stronger outcome: valid on any host wins, and a
// credential is only rejected when every host rejects it.
func mergeValidation(a, b blreport.Analysis) blreport.Analysis {
	if validationRank(b.Status) > validationRank(a.Status) {
		return b
	}
	return a
}

func validationRank(status blreport.ValidationStatus) int {
	switch status {
	case blreport.ValidationStatusValid:
		return 2
	case blreport.ValidationStatusInvalid, blreport.ValidationStatusRevoked:
		return 0
	default:
		return 1
	}
}

func detectBetterleaks(ctx context.Context, content []byte, workers int, verify bool, options DetectionOptions) ([]types.Finding, error) {
	gitLabURL := options.GitLabURL
	if gitLabURL == "" {
		gitLabURL = detectors.GetGitLabURL()
	}
	runtime, err := getBetterleaksRuntime(gitLabURL, verify, workers, options.Timeout)
	if err != nil {
		return nil, err
	}

	findings, err := runtime.scan(ctx, content, options.Path)
	return mapBetterleaksFindings(findings, rules.GetConfidenceFilter()), err
}

func mapBetterleaksFindings(findings []blreport.Finding, confidenceFilter []string) []types.Finding {
	mapped := make([]types.Finding, 0, len(findings))
	for _, finding := range findings {
		confidence := finding.Confidence
		switch finding.Analysis.Status {
		case blreport.ValidationStatusValid:
			confidence = "high-verified"
		case blreport.ValidationStatusInvalid, blreport.ValidationStatusRevoked:
			continue
		}
		if len(confidenceFilter) > 0 && !slices.Contains(confidenceFilter, confidence) {
			continue
		}
		value := finding.Match.Value
		if value == "" {
			value = finding.Match.Full
		}
		mapped = append(mapped, types.Finding{
			Pattern: types.PatternElement{Pattern: types.PatternPattern{
				Name:       "betterleaks/" + finding.RuleID,
				Confidence: confidence,
			}},
			Text:   value,
			Engine: EngineBetterleaks,
		})
	}
	return mapped
}

func (runtime *betterleaksRuntime) scan(ctx context.Context, content []byte, path string) ([]blreport.Finding, error) {
	attributes := map[string]string{}
	if path != "" {
		attributes[sources.AttrPath] = path
	}
	source := &sources.Reader{
		Content:    bytes.NewReader(content),
		Attributes: attributes,
		Prefilter:  runtime.prefilter,
	}

	var findings []blreport.Finding
	_, err := runtime.scanner.Scan(ctx, source, func(finding blreport.Finding) error {
		findings = append(findings, finding)
		return nil
	})
	if err != nil || runtime.analyzer == nil || len(findings) == 0 {
		return findings, err
	}

	validated := make([]blreport.Finding, 0, len(findings))
	err = runtime.analyzer.ValidateStream(ctx, func(ctx context.Context, yield func(blreport.Finding) error) error {
		for _, finding := range findings {
			if err := yield(finding); err != nil {
				return err
			}
		}
		return nil
	}, func(finding blreport.Finding) error {
		validated = append(validated, finding)
		return nil
	})
	if err != nil {
		return findings, err
	}
	if runtime.selfHostedAnalyzer == nil {
		return validated, nil
	}

	// Results arrive in completion order, so tag each GitLab finding with its index.
	err = runtime.selfHostedAnalyzer.ValidateStream(ctx, func(ctx context.Context, yield func(blreport.Finding) error) error {
		for i := range validated {
			if !isGitLabRule(validated[i].RuleID) {
				continue
			}
			finding := validated[i].Clone()
			finding.SetAttr(findingIndexAttr, strconv.Itoa(i))
			if err := yield(finding); err != nil {
				return err
			}
		}
		return nil
	}, func(finding blreport.Finding) error {
		i, err := strconv.Atoi(finding.Attr(findingIndexAttr))
		if err != nil || i < 0 || i >= len(validated) {
			return nil
		}
		validated[i].Analysis = mergeValidation(validated[i].Analysis, finding.Analysis)
		return nil
	})
	return validated, err
}
