package rules

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
	"github.com/rs/zerolog/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"gopkg.in/yaml.v3"
)

const ruleFileName = "rules.yml"

//go:embed rules.yaml
var builtinYAML []byte

type CompiledPattern struct {
	Pattern types.PatternElement
	regex   *regexp.Regexp
	token   bool
}

func (p CompiledPattern) FindAllIndex(text []byte) [][]int {
	hits := p.regex.FindAllIndex(text, -1)
	if !p.token {
		return hits
	}
	return slices.DeleteFunc(hits, func(hit []int) bool {
		start, end := hit[0], hit[1]
		if start > 0 && isTokenByte(text[start-1]) && text[start-1] != '=' {
			return true
		}
		if end < len(text) && isTokenByte(text[end]) {
			return true
		}
		// A dot followed by token characters is a format segment, not punctuation.
		return end+1 < len(text) && text[end] == '.' && isTokenByte(text[end+1])
	})
}

func isTokenByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '='
}

var loadBuiltins = sync.OnceValues(func() ([]CompiledPattern, error) {
	return parseRules(builtinYAML, "embedded rules.yaml")
})

func BuiltinPatterns() []CompiledPattern {
	patterns, err := loadBuiltins()
	if err != nil {
		log.Fatal().Err(err).Msg("Invalid embedded rules")
	}
	return slices.Clone(patterns)
}

var state = struct {
	sync.RWMutex
	patterns  []CompiledPattern
	detectors []detectors.Detector
	filter    []string
}{}

func parseRules(data []byte, source string) ([]CompiledPattern, error) {
	var definitions types.SecretsPatterns
	if err := yaml.Unmarshal(data, &definitions); err != nil {
		return nil, fmt.Errorf("%s: invalid YAML: %w", source, err)
	}
	patterns := make([]CompiledPattern, 0, len(definitions.Patterns))
	names := make(map[string]bool)
	for _, element := range definitions.Patterns {
		p := element.Pattern
		if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Regex) == "" || strings.TrimSpace(p.Confidence) == "" {
			return nil, fmt.Errorf("%s: rule %q requires a name, regex, and confidence", source, p.Name)
		}
		if names[p.Name] {
			return nil, fmt.Errorf("%s: duplicate rule name %q", source, p.Name)
		}
		names[p.Name] = true
		regex, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("%s: rule %q: invalid regex: %w", source, p.Name, err)
		}
		patterns = append(patterns, CompiledPattern{
			Pattern: element,
			regex:   regex,
			token:   source == "embedded rules.yaml" && p.Confidence == "high",
		})
	}
	return patterns, nil
}

func loadRules(path string) ([]CompiledPattern, error) {
	builtins, err := loadBuiltins()
	if err != nil {
		return nil, err
	}
	patterns := slices.Clone(builtins)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return patterns, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	custom, err := parseRules(data, path)
	if err != nil {
		return nil, err
	}
	for _, pattern := range custom {
		index := slices.IndexFunc(patterns, func(builtin CompiledPattern) bool {
			return builtin.Pattern.Pattern.Name == pattern.Pattern.Pattern.Name
		})
		if index >= 0 {
			patterns[index] = pattern
		} else {
			patterns = append(patterns, pattern)
		}
	}
	return patterns, nil
}

func InitRules(confidenceFilter []string) {
	patterns, err := loadRules(ruleFileName)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed loading rules")
		return
	}
	trufflehog := defaults.DefaultDetectors()
	if len(trufflehog) == 0 {
		log.Fatal().Msg("No TruffleHog detectors loaded")
		return
	}
	state.Lock()
	state.patterns = patterns
	state.detectors = trufflehog
	state.filter = slices.Clone(confidenceFilter)
	state.Unlock()
	log.Debug().Int("count", len(patterns)).Msg("Loaded embedded and local rules")
	log.Debug().Int("count", len(trufflehog)).Msg("Loaded TruffleHog rules")
}

func AppendPipeleekRules(patterns []types.PatternElement) []types.PatternElement {
	result := slices.Clone(patterns)
	for _, builtin := range BuiltinPatterns() {
		if !slices.ContainsFunc(result, func(p types.PatternElement) bool {
			return p.Pattern.Name == builtin.Pattern.Pattern.Name
		}) {
			result = append(result, builtin.Pattern)
		}
	}
	return result
}

func GetCompiledPatterns() []CompiledPattern {
	state.RLock()
	defer state.RUnlock()
	return slices.Clone(state.patterns)
}

func GetSecretsPatterns() types.SecretsPatterns {
	patterns := GetCompiledPatterns()
	result := types.SecretsPatterns{Patterns: make([]types.PatternElement, 0, len(patterns))}
	for _, pattern := range patterns {
		result.Patterns = append(result.Patterns, pattern.Pattern)
	}
	return result
}

func GetTruffleHogRules() []detectors.Detector {
	state.RLock()
	defer state.RUnlock()
	return slices.Clone(state.detectors)
}

func GetConfidenceFilter() []string {
	state.RLock()
	defer state.RUnlock()
	return slices.Clone(state.filter)
}
