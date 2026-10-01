package engine

import (
	"bytes"
	"context"
	"slices"
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

type betterleaksRuntimeKey struct {
	gitLabURL string
	verify    bool
	workers   int
	timeout   time.Duration
}

type betterleaksRuntime struct {
	scanner   *blscan.Scanner
	analyzer  *blanalyze.Analyzer
	prefilter sources.PrefilterFunc
}

var betterleaksRuntimes = struct {
	sync.Mutex
	items map[betterleaksRuntimeKey]*betterleaksRuntime
}{items: make(map[betterleaksRuntimeKey]*betterleaksRuntime)}

func getBetterleaksRuntime(gitLabURL string, verify bool, workers int, timeout time.Duration) (*betterleaksRuntime, error) {
	key := betterleaksRuntimeKey{
		gitLabURL: strings.TrimRight(gitLabURL, "/"),
		verify:    verify,
		workers:   workers,
		timeout:   timeout,
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
	rewriteGitLabRuleHosts(config, key.gitLabURL)

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
	}

	betterleaksRuntimes.items[key] = runtime
	return runtime, nil
}

func rewriteGitLabRuleHosts(config *blconfig.Config, gitLabURL string) {
	if gitLabURL == "" {
		return
	}
	for i := range config.Rules {
		if !strings.HasPrefix(config.Rules[i].ID, "gitlab-") {
			continue
		}
		config.Rules[i].ValidateExpr = strings.ReplaceAll(config.Rules[i].ValidateExpr, "https://gitlab.com", gitLabURL)
		config.Rules[i].AnalyzeExpr = strings.ReplaceAll(config.Rules[i].AnalyzeExpr, "https://gitlab.com", gitLabURL)
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
	return validated, nil
}
