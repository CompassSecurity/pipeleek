// Package filter classifies Renovate autodiscoverFilter values and reports
// whether they can be bypassed by an attacker-controlled repository path.
//
// It ports the pattern-matching semantics of Renovate's matchRegexOrGlobList /
// isRegexMatch helpers so that verdicts match what the actual bot would do.
package filter

import (
	"encoding/json"
	"regexp"
	"regexp/syntax"
	"strings"

	"github.com/gobwas/glob"
)

// PatternKind describes how a single pattern was classified.
type PatternKind int

const (
	// KindGlob is a plain glob pattern compiled with gobwas/glob.
	KindGlob PatternKind = iota
	// KindRegex is a well-formed regex delimited by /…/ or /…/i.
	KindRegex
	// KindMalformedRegexFallback looks like a regex (leading/trailing /) but
	// its body fails RE2 compilation. Renovate silently degrades to glob here.
	KindMalformedRegexFallback
)

// Verdict classifies the security impact of a finding.
type Verdict int

const (
	// Safe means the filter appears structurally sound.
	Safe Verdict = iota
	// Vulnerable means an attacker-controlled path can bypass the filter.
	Vulnerable
	// Broken means the filter is syntactically wrong and silently does nothing.
	Broken
	// NeedsReview means the pattern is ambiguous (e.g., RE2 vs JS divergence).
	NeedsReview
)

// String returns a human-readable label for structured log fields.
func (v Verdict) String() string {
	switch v {
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

// Finding is a single classifier result for one pattern or the filter list as a whole.
type Finding struct {
	// RuleID identifies the check: "V1"–"V4" for exploitable, "N2"–"N4" for broken/review, "INFO" for informational.
	RuleID string
	// Verdict is the security classification.
	Verdict Verdict
	// Pattern is the offending pattern, empty for list-level findings.
	Pattern string
	// Evidence contains adversarial inputs that passed the filter (probe findings only).
	Evidence []string
	// Message is a human-readable explanation.
	Message string
}

// Analyze parses filterValue (a single pattern string or a JSON array of
// pattern strings) and returns all findings in order of decreasing severity.
// Empty or whitespace-only inputs return nil.
func Analyze(filterValue string) []Finding {
	patterns := parsePatterns(filterValue)
	if len(patterns) == 0 {
		return nil
	}

	f := &filterList{patterns: patterns}
	var findings []Finding

	// List-level static rules.
	findings = append(findings, checkV1(patterns)...)
	findings = append(findings, checkV2(patterns)...)

	// Per-pattern static rules.
	for _, p := range patterns {
		findings = append(findings, checkN2(p)...)
		findings = append(findings, checkN4(p)...)
		if p.kind == KindRegex {
			findings = append(findings, checkV3(p)...)
		}
	}

	// Adversarial probe — catches V4 and confirms V3 with concrete evidence.
	findings = append(findings, probe(f, patterns)...)

	// Namespace-trust note — always emitted; represents residual risk that
	// static analysis cannot see.
	findings = append(findings, Finding{
		RuleID:  "INFO",
		Verdict: Safe,
		Message: "Even a structurally sound filter trusts every principal with project-creation rights in the matched namespaces; this residual risk cannot be verified statically.",
	})

	return findings
}

// ─── Internal types ───────────────────────────────────────────────────────────

type parsedPattern struct {
	raw     string
	negated bool
	kind    PatternKind
	body    string // regex body (delimiters and trailing i stripped)
	nocase  bool
	matchFn func(string) bool
}

type filterList struct {
	patterns []parsedPattern
}

// match implements Renovate's matchRegexOrGlobList semantics:
//   - empty list → false
//   - if positive patterns exist, at least one must match
//   - if negative patterns exist, none must match
func (f *filterList) match(input string) bool {
	if len(f.patterns) == 0 {
		return false
	}
	pos, neg := splitPosNeg(f.patterns)
	if len(pos) > 0 {
		anyPos := false
		for _, p := range pos {
			if p.matchFn(input) {
				anyPos = true
				break
			}
		}
		if !anyPos {
			return false
		}
	}
	for _, p := range neg {
		if p.matchFn(input) {
			return false
		}
	}
	return true
}

func splitPosNeg(ps []parsedPattern) (pos, neg []parsedPattern) {
	for _, p := range ps {
		if p.negated {
			neg = append(neg, p)
		} else {
			pos = append(pos, p)
		}
	}
	return
}

// ─── Pattern parsing ──────────────────────────────────────────────────────────

func parsePatterns(filterValue string) []parsedPattern {
	var items []string
	trimmed := strings.TrimSpace(filterValue)
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
			items = nil
		}
	}
	if len(items) == 0 {
		items = []string{filterValue}
	}

	var out []parsedPattern
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, classifyPattern(item))
	}
	return out
}

// ─── Classifier (Phase 2) — ports Renovate's isRegexMatch verbatim ───────────

var (
	reClassifyStart = regexp.MustCompile(`^!?/`)
	reClassifyEnd   = regexp.MustCompile(`/i?$`)

	// Pre-compiled regexes used by deriveGoodSample and bracesFirstAlt.
	reCharClass  = regexp.MustCompile(`\[[^\]]*\]`)
	reGroup      = regexp.MustCompile(`\([^)]*\)`)
	reQuantifier = regexp.MustCompile(`[+*?]\??`)
	reCurly      = regexp.MustCompile(`\{[^}]*\}`)
	reBraces     = regexp.MustCompile(`\{([^}]*)\}`)
)

func classifyPattern(raw string) parsedPattern {
	p := parsedPattern{raw: raw}

	negBody := raw
	if strings.HasPrefix(negBody, "!") {
		p.negated = true
		negBody = negBody[1:]
	}

	if reClassifyStart.MatchString(raw) && reClassifyEnd.MatchString(raw) {
		// Looks like a regex: /body/ or /body/i
		p.nocase = strings.HasSuffix(negBody, "/i")
		if p.nocase {
			p.body = negBody[1 : len(negBody)-2]
		} else {
			p.body = negBody[1 : len(negBody)-1]
		}

		regexBody := p.body
		if p.nocase {
			regexBody = "(?i)" + regexBody
		}

		re, err := regexp.Compile(regexBody)
		if err != nil {
			// RE2 compilation failed — Renovate falls back to treating as glob.
			p.kind = KindMalformedRegexFallback
			p.matchFn = buildGlobMatcher(negBody)
		} else {
			p.kind = KindRegex
			if p.nocase {
				p.matchFn = func(s string) bool { return re.MatchString(s) }
			} else {
				p.matchFn = re.MatchString
			}
		}
	} else {
		p.kind = KindGlob
		p.matchFn = buildGlobMatcher(negBody)
	}

	return p
}

// buildGlobMatcher compiles a gobwas/glob with separator '/' and case-folding.
// The '*' short-circuit is preserved as documented in matchRegexOrGlob.
func buildGlobMatcher(pattern string) func(string) bool {
	lower := strings.ToLower(pattern)
	if lower == "*" {
		return func(string) bool { return true }
	}
	g, err := glob.Compile(lower, '/')
	if err != nil {
		return func(string) bool { return false }
	}
	return func(s string) bool { return g.Match(strings.ToLower(s)) }
}

// ─── Static rules (Phase 4) ───────────────────────────────────────────────────

// checkV1: only negation patterns → positive gate is absent → everything passes.
func checkV1(ps []parsedPattern) []Finding {
	pos, neg := splitPosNeg(ps)
	if len(pos) == 0 && len(neg) > 0 {
		return []Finding{{
			RuleID:  "V1",
			Verdict: Vulnerable,
			Message: "Filter contains only negation patterns; Renovate matches every discovered repository that is not explicitly excluded, giving an attacker a bypass by using any path outside the deny-list.",
		}}
	}
	return nil
}

// checkV2: a bare "*" pattern matches every repository unconditionally.
func checkV2(ps []parsedPattern) []Finding {
	for _, p := range ps {
		if !p.negated && (p.raw == "*" || p.body == ".*") {
			return []Finding{{
				RuleID:  "V2",
				Verdict: Vulnerable,
				Pattern: p.raw,
				Message: `Wildcard pattern "*" matches every repository; the filter provides no scope restriction.`,
			}}
		}
	}
	return nil
}

// checkN2: a glob pattern with a leading "/" is half-delimited (looks like a
// regex but fails the end-delimiter test). The leading slash prevents any match
// against real GitLab paths that do not start with "/".
func checkN2(p parsedPattern) []Finding {
	if p.kind != KindGlob {
		return nil
	}
	raw := p.raw
	if p.negated {
		raw = raw[1:]
	}
	if strings.HasPrefix(raw, "/") {
		return []Finding{{
			RuleID:  "N2",
			Verdict: Broken,
			Pattern: p.raw,
			Message: "Glob pattern has a leading '/'; it resembles a regex but is missing the closing delimiter, so it is treated as a glob. The leading '/' means it will not match real GitLab paths.",
		}}
	}
	return nil
}

// checkN4: regex body failed RE2 compilation; Renovate may use a JS RegExp
// fallback (RENOVATE_X_IGNORE_RE2 or load failure) so the pattern could be
// valid in production but unverifiable here.
func checkN4(p parsedPattern) []Finding {
	if p.kind == KindMalformedRegexFallback {
		return []Finding{{
			RuleID:  "N4",
			Verdict: NeedsReview,
			Pattern: p.raw,
			Message: "Regex body failed RE2 compilation; Renovate may fall back to a JS RegExp engine where the pattern is valid. Verify manually whether the intended semantics are preserved.",
		}}
	}
	return nil
}

// checkV3: regex with no start anchor can match an attacker-controlled segment
// anywhere in the path (e.g. /myorg/ matches "evil/myorg-infra/x").
func checkV3(p parsedPattern) []Finding {
	if !isStartAnchored(p.body) {
		return []Finding{{
			RuleID:  "V3",
			Verdict: Vulnerable,
			Pattern: p.raw,
			Message: "Regex has no start anchor (^); it can match an attacker-controlled segment anywhere in the path, allowing namespace squatting or subpath injection.",
		}}
	}
	return nil
}

// isStartAnchored reports whether a regex body is anchored at the start of
// every alternation branch. Uses regexp/syntax so we do not hand-roll AST
// traversal.
func isStartAnchored(body string) bool {
	re, err := syntax.Parse(body, syntax.Perl)
	if err != nil {
		return false
	}
	re = re.Simplify()
	return anchored(re)
}

func anchored(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginText, syntax.OpBeginLine:
		return true
	case syntax.OpConcat:
		if len(re.Sub) > 0 {
			return anchored(re.Sub[0])
		}
	case syntax.OpCapture:
		if len(re.Sub) > 0 {
			return anchored(re.Sub[0])
		}
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !anchored(sub) {
				return false
			}
		}
		return len(re.Sub) > 0
	}
	return false
}

// ─── Adversarial probe (Phase 5) ──────────────────────────────────────────────

// probe generates a known-good sample for each positive pattern, then tests
// hostile mutations against the full filter. Any mutation that passes is
// recorded as a V4 finding (or upgrades a V3 finding with concrete evidence).
func probe(f *filterList, ps []parsedPattern) []Finding {
	pos, _ := splitPosNeg(ps)
	if len(pos) == 0 {
		return nil
	}

	// Collect patterns that already fired V3; we annotate those with evidence
	// instead of raising a separate V4.
	v3Patterns := map[string]bool{}
	for _, p := range pos {
		if p.kind == KindRegex && !isStartAnchored(p.body) {
			v3Patterns[p.raw] = true
		}
	}

	var findings []Finding
	seen := map[string]bool{} // deduplicate evidence across patterns

	for _, p := range pos {
		// Bare wildcard is already covered by V2; probing it adds no information.
		if p.raw == "*" {
			continue
		}

		sample := deriveGoodSample(p)
		if sample == "" {
			continue
		}

		// Sanity-check: sample should match the filter; if not the pattern is
		// already broken and covered by N-rules.
		if !f.match(sample) {
			continue
		}

		prefix := literalNamespacePrefix(p)
		mutations := hostileMutations(sample, prefix)

		var evidence []string
		for _, m := range mutations {
			if !seen[m] && f.match(m) {
				evidence = append(evidence, m)
				seen[m] = true
			}
		}

		if len(evidence) == 0 {
			continue
		}

		if v3Patterns[p.raw] {
			// Annotate V3 finding with concrete probe evidence rather than
			// raising a redundant V4.
			findings = append(findings, Finding{
				RuleID:   "V3",
				Verdict:  Vulnerable,
				Pattern:  p.raw,
				Evidence: evidence,
				Message:  "Regex has no start anchor; adversarial probe confirmed bypass.",
			})
		} else {
			findings = append(findings, Finding{
				RuleID:   "V4",
				Verdict:  Vulnerable,
				Pattern:  p.raw,
				Evidence: evidence,
				Message:  "Regex is anchored but lacks a trailing separator or end anchor; adversarial probe confirmed bypass via sibling-namespace squatting.",
			})
		}
	}

	return findings
}

// stripRegexBody strips the leading anchor and unescapes \/ in a regex body,
// returning a string that is closer to a literal path. Used by both
// deriveGoodSample and literalNamespacePrefix.
func stripRegexBody(body string) string {
	s := strings.TrimPrefix(body, "^")
	return strings.ReplaceAll(s, `\/`, `/`)
}

// deriveGoodSample synthesises a concrete path that should be matched by p.
func deriveGoodSample(p parsedPattern) string {
	raw := p.raw
	if p.negated {
		raw = raw[1:]
	}

	var s string
	switch p.kind {
	case KindRegex:
		// Start from the body, strip anchors, unescape \/, sanitise metacharacters.
		s = stripRegexBody(p.body)
		s = strings.TrimSuffix(s, "$")
		// Replace character classes and quantifiers with a literal token.
		s = reCharClass.ReplaceAllString(s, "zsample")
		s = reGroup.ReplaceAllString(s, "zsample")
		s = reQuantifier.ReplaceAllString(s, "")
		s = reCurly.ReplaceAllString(s, "")
		s = strings.ReplaceAll(s, ".", "x")
	default:
		// Glob
		s = raw
		s = strings.ReplaceAll(s, "**", "zsample")
		s = strings.ReplaceAll(s, "*", "zsample")
		s = bracesFirstAlt(s)
	}

	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "/") {
		s += "/zsample"
	}
	return s
}

// literalNamespacePrefix returns the literal namespace segment of a pattern
// (everything before the first '/' or metacharacter).
func literalNamespacePrefix(p parsedPattern) string {
	raw := p.raw
	if p.negated {
		raw = raw[1:]
	}

	var s string
	if p.kind == KindRegex {
		s = stripRegexBody(p.body)
	} else {
		s = raw
	}

	s = scanLiteralPrefix(s)
	if idx := strings.Index(s, "/"); idx >= 0 {
		s = s[:idx]
	}
	return strings.ToLower(s)
}

// scanLiteralPrefix returns the portion of s before the first glob/regex metacharacter.
func scanLiteralPrefix(s string) string {
	for i, c := range s {
		if strings.ContainsRune(`*?{[(\\^$|`, c) {
			return s[:i]
		}
	}
	return s
}

// hostileMutations returns adversarial GitLab paths designed to bypass the
// filter via squatting, subpath injection, or leading-prefix bypass.
func hostileMutations(sample, prefix string) []string {
	if prefix == "" {
		return []string{"attacker/" + sample}
	}
	return []string{
		"attacker/" + sample,
		prefix + "-evil/x",
		"evil-" + prefix + "/x",
		prefix + "evil/x",
		"attacker/" + prefix + "/x",
		"attacker/" + prefix,
		"attacker/repo-" + prefix,
	}
}

// bracesFirstAlt replaces {a,b,c} with the first alternative a.
func bracesFirstAlt(s string) string {
	return reBraces.ReplaceAllStringFunc(s, func(m string) string {
		inner := m[1 : len(m)-1]
		if idx := strings.Index(inner, ","); idx >= 0 {
			return strings.TrimSpace(inner[:idx])
		}
		return inner
	})
}
