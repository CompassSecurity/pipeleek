package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Phase 2: classifier unit tests ──────────────────────────────────────────

func TestClassifyPattern(t *testing.T) {
	tests := []struct {
		raw      string
		kind     PatternKind
		negated  bool
		nocase   bool
		body     string
	}{
		{"/myorg/", KindRegex, false, false, "myorg"},
		{"/^myorg/", KindRegex, false, false, "^myorg"},
		{"/^myorg\\//", KindRegex, false, false, `^myorg\/`},
		{"/^myorg\\//i", KindRegex, false, true, `^myorg\/`},
		{"!/^myorg\\//", KindRegex, true, false, `^myorg\/`},
		{"myorg/*", KindGlob, false, false, ""},
		{"MatthiasLohr/*", KindGlob, false, false, ""},
		{"haproxy-haptic/*", KindGlob, false, false, ""},
		{"!my-org/old-*", KindGlob, true, false, ""},
		{"pinarnet", KindGlob, false, false, ""},
		// Half-delimited: starts with / but doesn't end with /i? — classified as glob.
		{"/gms-squared/support/**", KindGlob, false, false, ""},
		{"commonground/{nlx,core}/**", KindGlob, false, false, ""},
		{"gemseo/dev/gemseo", KindGlob, false, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			p := classifyPattern(tt.raw)
			assert.Equal(t, tt.kind, p.kind, "kind")
			assert.Equal(t, tt.negated, p.negated, "negated")
			assert.Equal(t, tt.nocase, p.nocase, "nocase")
			if tt.body != "" {
				assert.Equal(t, tt.body, p.body, "body")
			}
		})
	}
}

// Half-delimited pattern must be treated as glob (not regex).
func TestClassifyPattern_HalfDelimitedIsGlob(t *testing.T) {
	p := classifyPattern("/gms/support/**")
	assert.Equal(t, KindGlob, p.kind, "half-delimited must be KindGlob")
}

// ─── Phase 3: list-semantics unit tests ──────────────────────────────────────

func TestFilterListMatch_PositiveOnly(t *testing.T) {
	f := &filterList{patterns: []parsedPattern{
		classifyPattern("myorg/*"),
	}}
	assert.True(t, f.match("myorg/project"))
	assert.True(t, f.match("myorg/anything"))
	assert.False(t, f.match("other/project"))
	assert.False(t, f.match("evil-myorg/project"))
}

func TestFilterListMatch_NegationOnly(t *testing.T) {
	// V1 scenario: only negation → everything passes unless excluded.
	f := &filterList{patterns: []parsedPattern{
		classifyPattern("!my-org/old-*"),
	}}
	assert.True(t, f.match("my-org/newproject"), "not excluded → passes")
	assert.True(t, f.match("attacker/evil"), "not excluded → passes")
	assert.False(t, f.match("my-org/old-thing"), "excluded → blocked")
}

func TestFilterListMatch_MixedPosNeg(t *testing.T) {
	f := &filterList{patterns: []parsedPattern{
		classifyPattern("myorg/*"),
		classifyPattern("!myorg/skip-*"),
	}}
	assert.True(t, f.match("myorg/project"))
	assert.False(t, f.match("myorg/skip-this"))
	assert.False(t, f.match("other/project"))
}

func TestFilterListMatch_WildcardShortCircuit(t *testing.T) {
	f := &filterList{patterns: []parsedPattern{classifyPattern("*")}}
	assert.True(t, f.match("anything/goes"))
	assert.True(t, f.match("a/b/c"))
}

func TestFilterListMatch_Regex(t *testing.T) {
	patterns := []parsedPattern{classifyPattern("/^myorg\\//") }
	f := &filterList{patterns: patterns}
	assert.True(t, f.match("myorg/project"))
	assert.False(t, f.match("myorg-evil/project"))
	assert.False(t, f.match("evil/myorg/project"))
}

func TestFilterListMatch_RegexNoAnchor(t *testing.T) {
	patterns := []parsedPattern{classifyPattern("/myorg/") }
	f := &filterList{patterns: patterns}
	assert.True(t, f.match("myorg/project"))
	// Unanchored — attacker subpath bypass.
	assert.True(t, f.match("evil/myorg/x"))
}

// ─── Phase 6: Analyze corpus ─────────────────────────────────────────────────

func verdictOf(findings []Finding) Verdict {
	for _, f := range findings {
		if f.Verdict == Vulnerable {
			return Vulnerable
		}
	}
	for _, f := range findings {
		if f.Verdict == Broken {
			return Broken
		}
	}
	for _, f := range findings {
		if f.Verdict == NeedsReview {
			return NeedsReview
		}
	}
	return Safe
}

func hasRule(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestAnalyze_Corpus(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantVerdict    Verdict
		wantRules      []string // must all be present
		wantNoRules    []string // must all be absent
		wantEvidence   bool     // at least one finding must have evidence
	}{
		{
			name:        "safe glob namespace wildcard",
			input:       "MatthiasLohr/*",
			wantVerdict: Safe,
			wantRules:   []string{"INFO"},
			wantNoRules: []string{"V1", "V2", "V3", "V4", "N1", "N2"},
		},
		{
			name:        "safe glob with brace expansion",
			input:       `commonground/{nlx,core,don,haven,fsc}/**`,
			wantVerdict: Safe,
			wantRules:   []string{"INFO"},
			wantNoRules: []string{"V1", "V2", "V3", "V4"},
		},
		{
			name:        "safe literal path",
			input:       "gemseo/dev/gemseo",
			wantVerdict: Safe,
			wantRules:   []string{"INFO"},
			wantNoRules: []string{"V1", "V2", "V3", "V4", "N1", "N2"},
		},
		{
			name:        "safe glob hyphen-namespace wildcard",
			input:       "haproxy-haptic/*",
			wantVerdict: Safe,
			wantRules:   []string{"INFO"},
			wantNoRules: []string{"V1", "V2", "V3", "V4", "N1", "N2"},
		},
		{
			name:        "N2 broken half-delimited leading slash",
			input:       "/gms-squared/support/**",
			wantVerdict: Broken,
			wantRules:   []string{"N2", "INFO"},
			wantNoRules: []string{"V1", "V2", "V3", "V4"},
		},
		{
			name:        "N1 broken no slash",
			input:       `["pinarnet"]`,
			wantVerdict: Broken,
			wantRules:   []string{"N1", "INFO"},
			wantNoRules: []string{"V1", "V2", "V3", "V4"},
		},
		{
			name:         "V3 vulnerable unanchored regex",
			input:        "/myorg/",
			wantVerdict:  Vulnerable,
			wantRules:    []string{"V3", "INFO"},
			wantEvidence: true,
		},
		{
			name:         "V4 vulnerable anchored but no separator",
			input:        "/^myorg/",
			wantVerdict:  Vulnerable,
			wantRules:    []string{"V4", "INFO"},
			wantNoRules:  []string{"V3"},
			wantEvidence: true,
		},
		{
			name:        "safe anchored regex with separator",
			input:       `/^myorg\//`,
			wantVerdict: Safe,
			wantRules:   []string{"INFO"},
			wantNoRules: []string{"V1", "V2", "V3", "V4"},
		},
		{
			name:        "V1 vulnerable only-negation list",
			input:       `["!my-org/old-*"]`,
			wantVerdict: Vulnerable,
			wantRules:   []string{"V1", "INFO"},
			wantNoRules: []string{"V2", "V3", "V4"},
		},
		{
			name:        "V2 vulnerable bare wildcard",
			input:       "*",
			wantVerdict: Vulnerable,
			wantRules:   []string{"V2", "INFO"},
			wantNoRules: []string{"V3", "V4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Analyze(tt.input)
			require.NotEmpty(t, findings, "Analyze must return at least the INFO finding")

			assert.Equal(t, tt.wantVerdict, verdictOf(findings), "overall verdict")

			for _, r := range tt.wantRules {
				assert.True(t, hasRule(findings, r), "expected rule %s to be present", r)
			}
			for _, r := range tt.wantNoRules {
				assert.False(t, hasRule(findings, r), "expected rule %s to be absent", r)
			}
			if tt.wantEvidence {
				hasEv := false
				for _, f := range findings {
					if len(f.Evidence) > 0 {
						hasEv = true
						break
					}
				}
				assert.True(t, hasEv, "expected at least one finding with adversarial evidence")
			}
		})
	}
}

// ─── Additional edge-case tests ───────────────────────────────────────────────

func TestAnalyze_EmptyInput(t *testing.T) {
	assert.Nil(t, Analyze(""))
	assert.Nil(t, Analyze("   "))
}

func TestAnalyze_JSONArrayMultiPattern(t *testing.T) {
	findings := Analyze(`["myorg/*", "otherorg/**"]`)
	assert.Equal(t, Safe, verdictOf(findings))
	assert.True(t, hasRule(findings, "INFO"))
}

func TestAnalyze_JSONArrayMixedPosNeg_Safe(t *testing.T) {
	findings := Analyze(`["myorg/*", "!myorg/old-*"]`)
	assert.Equal(t, Safe, verdictOf(findings))
}

func TestAnalyze_MalformedRegexFallback(t *testing.T) {
	// Pattern that looks like a regex but uses a lookahead (invalid in RE2).
	findings := Analyze("/(?=myorg)/")
	assert.True(t, hasRule(findings, "N4"), "N4 should fire for RE2-incompatible regex")
	assert.Equal(t, NeedsReview, verdictOf(findings))
}

func TestAnalyze_RegexWithCaseInsensitiveFlag(t *testing.T) {
	findings := Analyze("/^myorg\\//i")
	// Anchored + separator → safe even with /i flag
	assert.Equal(t, Safe, verdictOf(findings))
}

func TestIsStartAnchored(t *testing.T) {
	assert.False(t, isStartAnchored("myorg"))
	assert.True(t, isStartAnchored("^myorg"))
	assert.True(t, isStartAnchored(`^myorg\/`))
	assert.False(t, isStartAnchored("myorg|other"))
	assert.True(t, isStartAnchored("^myorg|^other"))
	assert.False(t, isStartAnchored("^myorg|other")) // one branch unanchored
}

func TestVerdictString(t *testing.T) {
	assert.Equal(t, "safe", Safe.String())
	assert.Equal(t, "vulnerable", Vulnerable.String())
	assert.Equal(t, "broken", Broken.String())
	assert.Equal(t, "needs_review", NeedsReview.String())
}
