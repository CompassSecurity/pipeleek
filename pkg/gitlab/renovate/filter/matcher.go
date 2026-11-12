package filter

import (
	"encoding/json"
	"regexp"
	"regexp/syntax"
	"strings"

	minimatch "github.com/benjaminnkem/minimatch-go"
	"gopkg.in/yaml.v3"
)

type PatternKind int

const (
	KindGlob PatternKind = iota
	KindRegex
	KindMalformedRegexFallback
)

type Verdict int

const (
	Safe Verdict = iota
	Vulnerable
	Broken
	NeedsReview
)

func (verdict Verdict) String() string {
	switch verdict {
	case Safe:
		return "safe"
	case Vulnerable:
		return "vulnerable"
	case Broken:
		return "broken"
	case NeedsReview:
		return "needs_review"
	default:
		return "unknown"
	}
}

type Finding struct {
	RuleID   string
	Verdict  Verdict
	Pattern  string
	Evidence []string
	Message  string
}

const (
	RuleIDInfo                    = "info"
	RuleIDNegationOnlyFilter      = "negation-only-filter"
	RuleIDUnrestrictedWildcard    = "unrestricted-wildcard"
	RuleIDUnanchoredRegex         = "unanchored-regex"
	RuleIDPathBoundaryBypass      = "path-boundary-bypass"
	RuleIDUnfilteredAutodiscovery = "unfiltered-autodiscovery"
	RuleIDLeadingSlashGlob        = "leading-slash-glob"
	RuleIDRegexEngineReview       = "regex-engine-review"
	RuleIDUnsupportedExtglob      = "unsupported-extglob"
	RuleIDUnresolvedVariable      = "unresolved-variable"
	RuleIDTopicOnlyAutodiscovery  = "topic-only-autodiscovery"
	RuleIDNamespaceScopeReview    = "namespace-scope-unresolved"
)

type GitLabProjectPathValues struct {
	ProjectPath      string
	ProjectNamespace string
	RootNamespace    string
}

func Analyze(filterValue string) []Finding {
	findings := AnalyzeWithGitLabProjectPaths(filterValue, GitLabProjectPathValues{})
	if strings.TrimSpace(filterValue) != "" {
		findings = append(findings, Finding{RuleID: RuleIDInfo, Verdict: Safe, Message: "No candidate match does not prove that the filter is safe."})
	}
	return findings
}

func AnalyzeWithGitLabProjectPaths(filterValue string, paths GitLabProjectPathValues) []Finding {
	var findings []Finding
	result := analyzeCandidates(filterValue, paths)
	if len(result.Evidence) > 0 {
		findings = append(findings, Finding{
			RuleID: result.RuleID, Verdict: Vulnerable, Pattern: result.Pattern, Evidence: result.Evidence,
			Message: "The filter matches a candidate path outside the identified namespace roots; verify its availability and the intended scope.",
		})
	}
	if result.Review {
		findings = append(findings, Finding{RuleID: result.ReviewRule, Verdict: NeedsReview, Pattern: filterValue, Message: "The filter could not be analyzed reliably; review the configuration manually."})
	}
	for _, pattern := range parsePatterns(filterValue) {
		if pattern.kind == KindGlob && strings.HasPrefix(strings.TrimPrefix(pattern.raw, "!"), "/") {
			findings = append(findings, Finding{RuleID: RuleIDLeadingSlashGlob, Verdict: Broken, Pattern: pattern.raw, Message: "A leading slash prevents this glob from matching GitLab paths."})
		}
	}
	return findings
}

func AnalyzeUnfilteredAutodiscovery() []Finding {
	return []Finding{{RuleID: RuleIDUnfilteredAutodiscovery, Verdict: Vulnerable, Message: "Autodiscovery is enabled without a scope filter."}}
}

func AnalyzeTopicOnlyAutodiscovery(topics string) []Finding {
	return []Finding{{RuleID: RuleIDTopicOnlyAutodiscovery, Verdict: NeedsReview, Pattern: topics, Message: "Autodiscovery is scoped only by project topics; verify who can assign matching topics."}}
}

type parsedPattern struct {
	raw      string
	negated  bool
	kind     PatternKind
	body     string
	nocase   bool
	matchFn  func(string) bool
	matchErr error
}

type filterList struct{ patterns []parsedPattern }

func (list *filterList) match(input string) bool {
	if len(list.patterns) == 0 {
		return false
	}
	positive, matched := false, false
	for _, pattern := range list.patterns {
		if pattern.negated {
			if pattern.matchFn(input) {
				return false
			}
		} else {
			positive = true
			matched = matched || pattern.matchFn(input)
		}
	}
	return !positive || matched
}

func splitPosNeg(patterns []parsedPattern) (positive, negative []parsedPattern) {
	for _, pattern := range patterns {
		if pattern.negated {
			negative = append(negative, pattern)
		} else {
			positive = append(positive, pattern)
		}
	}
	return
}

var reEnvironmentVariable = regexp.MustCompile(`\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})`)
var reLiteralGitLabSegment = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func parsePatterns(value string) []parsedPattern {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	items := []string{value}
	if strings.HasPrefix(value, "[") {
		var array []string
		if json.Unmarshal([]byte(value), &array) == nil || yaml.Unmarshal([]byte(value), &array) == nil {
			items = array
		}
	}
	var patterns []parsedPattern
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			patterns = append(patterns, classifyPattern(item))
		}
	}
	return patterns
}

func classifyPattern(raw string) parsedPattern {
	pattern := parsedPattern{raw: raw, negated: strings.HasPrefix(raw, "!")}
	body := strings.TrimPrefix(raw, "!")
	if strings.HasPrefix(body, "/") && (strings.HasSuffix(body, "/") || strings.HasSuffix(body, "/i")) && len(body) > 1 {
		pattern.nocase = strings.HasSuffix(body, "/i")
		end := len(body) - 1
		if pattern.nocase {
			end--
		}
		if end < 1 {
			pattern.kind = KindMalformedRegexFallback
			pattern.matchFn = func(string) bool { return false }
			return pattern
		}
		pattern.body = body[1:end]
		expression := pattern.body
		if pattern.nocase {
			expression = "(?i)" + expression
		}
		compiled, err := regexp.Compile(expression)
		if err != nil {
			pattern.kind = KindMalformedRegexFallback
			pattern.matchFn = func(string) bool { return false }
		} else {
			pattern.kind = KindRegex
			pattern.matchFn = compiled.MatchString
		}
		return pattern
	}
	matcher, err := minimatch.NewMinimatch(raw, minimatch.Options{Dot: true, NoCase: true, Platform: "linux"})
	if err != nil {
		pattern.matchErr = err
		pattern.matchFn = func(string) bool { return false }
	} else if pattern.negated {
		pattern.matchFn = func(input string) bool { return !matcher.Match(input) }
	} else if raw == "*" {
		pattern.matchFn = func(string) bool { return true }
	} else {
		pattern.matchFn = matcher.Match
	}
	return pattern
}

type namespaceExtglob struct {
	operator     byte
	alternatives []string
}

func parseNamespaceExtglob(pattern string) (namespaceExtglob, bool) {
	var result namespaceExtglob
	if len(pattern) < 5 || !strings.ContainsRune("@+?*", rune(pattern[0])) || pattern[1] != '(' {
		return result, false
	}
	close := strings.IndexByte(pattern, ')')
	if close < 0 || strings.ContainsAny(pattern[2:close], "()") || !strings.Contains(pattern[close+1:], "/") {
		return result, false
	}
	result.operator = pattern[0]
	result.alternatives = strings.Split(pattern[2:close], "|")
	if len(result.alternatives) < 2 {
		return namespaceExtglob{}, false
	}
	for _, alternative := range result.alternatives {
		if !isLiteralGitLabSegment(alternative) {
			return namespaceExtglob{}, false
		}
	}
	return result, true
}

func isLiteralGitLabSegment(segment string) bool {
	return reLiteralGitLabSegment.MatchString(segment)
}

func validGitLabProbePath(path string) bool {
	segments := strings.Split(path, "/")
	if len(segments) < 2 {
		return false
	}
	for _, segment := range segments {
		if !isLiteralGitLabSegment(segment) || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func stripRegexBody(body string) string {
	return strings.ReplaceAll(strings.TrimPrefix(body, "^"), `\/`, `/`)
}

func scanLiteralPrefix(value string, regex bool) string {
	for index, character := range value {
		if strings.ContainsRune(`*?{[(\^$|`, character) || regex && character == '.' {
			return value[:index]
		}
	}
	return value
}

func isStartAnchored(body string) bool {
	expression, err := syntax.Parse(body, syntax.Perl)
	if err != nil {
		return false
	}
	return anchored(expression.Simplify())
}

func anchored(expression *syntax.Regexp) bool {
	switch expression.Op {
	case syntax.OpBeginText, syntax.OpBeginLine:
		return true
	case syntax.OpConcat, syntax.OpCapture:
		return len(expression.Sub) > 0 && anchored(expression.Sub[0])
	case syntax.OpAlternate:
		for _, branch := range expression.Sub {
			if !anchored(branch) {
				return false
			}
		}
		return len(expression.Sub) > 0
	}
	return false
}
