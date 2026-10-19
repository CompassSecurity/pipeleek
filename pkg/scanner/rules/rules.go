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
	Pattern                types.PatternElement
	regex                  *regexp.Regexp
	enforceTokenBoundaries bool
}

func (p CompiledPattern) FindAllIndex(text []byte) [][]int {
	hits := p.regex.FindAllIndex(text, -1)
	if !p.enforceTokenBoundaries {
		return hits
	}
	// ANSI CSI sequences around a token are formatting, not token characters.
	return slices.DeleteFunc(hits, func(hit []int) bool {
		start, end := hit[0], hit[1]
		if previous, ok := previousVisibleByte(text, start); ok && isTokenByte(previous) && previous != '=' {
			return true
		}
		next, nextIndex, ok := nextVisibleByte(text, end)
		if ok && isTokenByte(next) {
			return true
		}
		// A dot followed by token characters is a format segment, not punctuation.
		if ok && next == '.' {
			afterDot, _, hasAfterDot := nextVisibleByte(text, nextIndex+1)
			return hasAfterDot && isTokenByte(afterDot)
		}
		return false
	})
}

func previousVisibleByte(text []byte, index int) (byte, bool) {
	for index > 0 {
		if start, ok := ansiCSIEndingAt(text, index); ok {
			index = start
			continue
		}
		return text[index-1], true
	}
	return 0, false
}

func nextVisibleByte(text []byte, index int) (byte, int, bool) {
	for index < len(text) {
		if end, ok := ansiCSIStartingAt(text, index); ok {
			index = end
			continue
		}
		return text[index], index, true
	}
	return 0, 0, false
}

func ansiCSIEndingAt(text []byte, end int) (int, bool) {
	if end == 0 || text[end-1] < 0x40 || text[end-1] > 0x7e {
		return 0, false
	}
	for start := end - 2; start >= 0; start-- {
		if text[start] == '[' {
			if start == 0 || text[start-1] != 0x1b {
				return 0, false
			}
			for i := start + 2; i < end-1; i++ {
				if text[i] < 0x20 || text[i] > 0x3f {
					return 0, false
				}
			}
			return start - 1, true
		}
		if text[start] < 0x20 || text[start] > 0x3f {
			return 0, false
		}
	}
	return 0, false
}

func ansiCSIStartingAt(text []byte, start int) (int, bool) {
	if start+1 >= len(text) || text[start] != 0x1b || text[start+1] != '[' {
		return 0, false
	}
	for end := start + 2; end < len(text); end++ {
		if text[end] >= 0x40 && text[end] <= 0x7e {
			return end + 1, true
		}
		if text[end] < 0x20 || text[end] > 0x3f {
			return 0, false
		}
	}
	return 0, false
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
			Pattern:                element,
			regex:                  regex,
			enforceTokenBoundaries: p.Token,
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
	data, err := os.ReadFile(path) // #nosec G304 -- InitRules supplies the fixed local rules.yml path; alternate paths are used only by tests.
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
	if len(confidenceFilter) > 0 {
		log.Debug().Strs("filter", confidenceFilter).Msg("Applying confidence filter")
	}
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
