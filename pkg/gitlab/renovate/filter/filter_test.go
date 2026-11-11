package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Phase 2: classifier unit tests ──────────────────────────────────────────

func TestClassifyPattern(t *testing.T) {
	tests := []struct {
		raw     string
		kind    PatternKind
		negated bool
		nocase  bool
		body    string
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

func TestClassifyPattern_RegexInsensitiveMatchesUppercaseLiteral(t *testing.T) {
	p := classifyPattern("/^MyOrg\\//i")
	assert.Equal(t, KindRegex, p.kind)
	assert.True(t, p.matchFn("myorg/project"))
	assert.True(t, p.matchFn("MYORG/project"))
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
	patterns := []parsedPattern{classifyPattern("/^myorg\\//")}
	f := &filterList{patterns: patterns}
	assert.True(t, f.match("myorg/project"))
	assert.False(t, f.match("myorg-evil/project"))
	assert.False(t, f.match("evil/myorg/project"))
}

func TestFilterListMatch_RegexNoAnchor(t *testing.T) {
	patterns := []parsedPattern{classifyPattern("/myorg/")}
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

func TestPlusExtglobSuffixWildcardMatchesSiblingNamespaces(t *testing.T) {
	matcher := classifyPattern("+(myname|myname-renovate|myname-projects)*/*").matchFn
	assert.True(t, matcher("myname/foo"))
	assert.True(t, matcher("myname-renovate/foo"))
	assert.True(t, matcher("myname-projects/foo"))
	assert.True(t, matcher("myname-anything/foo"))
	assert.True(t, matcher("mynamexyz/foo"))
	assert.False(t, matcher("othername/foo"))
}

func TestAnalyze_ValidGitLabSiblingNamespaceCases(t *testing.T) {
	tests := []struct {
		name           string
		pattern        string
		verifiedBypass string
	}{
		{name: "regex numeric class with repetition", pattern: `/^myname[0-9]+/`, verifiedBypass: "myname0/project"},
		{name: "regex anchored alternatives without path boundary", pattern: `/^myname|^othername/`, verifiedBypass: "mynamea/project"},
		{name: "glob single-character wildcard", pattern: "myname?/*", verifiedBypass: "mynamea/project"},
		{name: "glob numeric character class", pattern: "myname[0-9]/*", verifiedBypass: "myname0/project"},
		{name: "glob brace alternatives with suffix wildcard", pattern: "myname{a,b}*/*", verifiedBypass: "mynameaa/project"},
		{name: "extglob plus repetition", pattern: "+(myname|other)/*", verifiedBypass: "mynameother/project"},
		{name: "extglob at with suffix wildcard", pattern: "@(myname|other)*/*", verifiedBypass: "mynamea/project"},
		{name: "extglob optional with suffix wildcard", pattern: "?(myname|other)*/*", verifiedBypass: "mynamea/project"},
		{name: "extglob zero-or-more with suffix wildcard", pattern: "*(myname|other)*/*", verifiedBypass: "mynamea/project"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Analyze(tt.pattern)
			assert.Equal(t, Vulnerable, verdictOf(findings))

			var evidence []string
			for _, finding := range findings {
				evidence = append(evidence, finding.Evidence...)
			}
			require.NotEmpty(t, evidence, "vulnerable result must include a matching path")
			assert.Contains(t, evidence, tt.verifiedBypass, "must include the path independently verified against Renovate's matcher")
			for _, path := range evidence {
				for i := 0; i < len(path); i++ {
					c := path[i]
					assert.True(t, c == '/' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-', "evidence path %q contains a non-GitLab path character %q", path, c)
				}
			}
		})
	}
}

func TestAnalyze_UnfilteredAutodiscovery(t *testing.T) {
	findings := AnalyzeUnfilteredAutodiscovery()
	require.Len(t, findings, 1)
	assert.Equal(t, RuleIDUnfilteredAutodiscovery, findings[0].RuleID)
	assert.Equal(t, Vulnerable, findings[0].Verdict)
}

func TestAnalyzeTopicOnlyAutodiscovery(t *testing.T) {
	findings := AnalyzeTopicOnlyAutodiscovery(`['renovate-managed']`)
	require.Len(t, findings, 1)
	assert.Equal(t, RuleIDTopicOnlyAutodiscovery, findings[0].RuleID)
	assert.Equal(t, NeedsReview, findings[0].Verdict)
	assert.Equal(t, `['renovate-managed']`, findings[0].Pattern)
}

func TestAnalyzeWithGitLabProjectPaths(t *testing.T) {
	paths := GitLabProjectPathValues{
		ProjectPath:      "group/subgroup/renovate",
		ProjectNamespace: "group/subgroup",
		RootNamespace:    "group",
	}

	assert.Equal(t, Safe, verdictOf(AnalyzeWithGitLabProjectPaths("$CI_PROJECT_PATH", paths)))
	assert.Equal(t, Safe, verdictOf(AnalyzeWithGitLabProjectPaths("${CI_PROJECT_NAMESPACE}/**", paths)))
	assert.Equal(t, Safe, verdictOf(AnalyzeWithGitLabProjectPaths("${CI_PROJECT_ROOT_NAMESPACE}/**", paths)))
	sylvaFilter := `["${CI_PROJECT_ROOT_NAMESPACE}/**", "!/.*-deletion_scheduled-.*/", "!/.*/forks//", "!/.*renovate-test.*/"]`
	assert.Equal(t, Safe, verdictOf(AnalyzeWithGitLabProjectPaths(sylvaFilter, paths)))

	findings := AnalyzeWithGitLabProjectPaths("$CI_PROJECT_ROOT_NAMESPACE*/*", paths)
	assert.Equal(t, Vulnerable, verdictOf(findings))
	assert.True(t, hasRule(findings, RuleIDPathBoundaryBypass))
	for _, finding := range findings {
		assert.Contains(t, finding.Evidence, "groupa/project")
		break
	}

	findings = AnalyzeWithGitLabProjectPaths("$CI_PROJECT_PATH*/*", paths)
	assert.Equal(t, Vulnerable, verdictOf(findings))
	assert.True(t, hasRule(findings, RuleIDPathBoundaryBypass))
	for _, finding := range findings {
		assert.Contains(t, finding.Evidence, "group/subgroup/renovatea/project")
		break
	}

	findings = AnalyzeWithGitLabProjectPaths("$CI_PROJECT_PATH", GitLabProjectPathValues{})
	assert.Equal(t, NeedsReview, verdictOf(findings))
	assert.True(t, hasRule(findings, RuleIDUnresolvedVariable))

	findings = AnalyzeWithGitLabProjectPaths("${RENOVATE_PROJECT}", paths)
	assert.Equal(t, NeedsReview, verdictOf(findings))
	assert.True(t, hasRule(findings, RuleIDUnresolvedVariable))

	for _, value := range []string{"$CI_PROJECT_PATH_SLUG", "${CI_PROJECT_PATH}"} {
		findings = AnalyzeWithGitLabProjectPaths(value, GitLabProjectPathValues{})
		assert.True(t, hasRule(findings, RuleIDUnresolvedVariable), value)
	}
	findings = AnalyzeWithGitLabProjectPaths("$CI_PROJECT_PATH_SLUG", paths)
	assert.True(t, hasRule(findings, RuleIDUnresolvedVariable))

	findings = AnalyzeWithGitLabProjectPaths(`["*", "trusted/${CUSTOM}"]`, paths)
	assert.True(t, hasRule(findings, RuleIDUnrestrictedWildcard))
	assert.True(t, hasRule(findings, RuleIDUnresolvedVariable))
	for _, value := range []string{`["*", "!${CUSTOM}"]`, `["*", "${CUSTOM}"]`, `["!other/*", "trusted/${CUSTOM}"]`} {
		findings = AnalyzeWithGitLabProjectPaths(value, paths)
		assert.Equal(t, NeedsReview, verdictOf(findings), value)
		assert.True(t, hasRule(findings, RuleIDUnresolvedVariable), value)
	}
}

func TestAnalyzeRegexDotDoesNotExtendNamespacePrefix(t *testing.T) {
	findings := Analyze(`/^acme\/.*$/`)
	assert.False(t, hasRule(findings, RuleIDPathBoundaryBypass))
	assert.Equal(t, "acme.name", literalNamespacePrefix(classifyPattern("acme.name*/*")))
}

func TestAnalyze_UnsupportedExtglobNeedsReview(t *testing.T) {
	findings := Analyze("@(myname|+(other|else))/*")
	assert.Equal(t, NeedsReview, verdictOf(findings))
	assert.True(t, hasRule(findings, RuleIDUnsupportedExtglob))
}

func TestProbeAttributesVulnerabilityToMatchingPositivePattern(t *testing.T) {
	findings := Analyze(`["myname/*", "myname?/*"]`)
	for _, finding := range findings {
		if finding.RuleID == RuleIDPathBoundaryBypass {
			assert.Equal(t, "myname?/*", finding.Pattern)
			return
		}
	}
	t.Fatal("expected the broad positive pattern to be reported as vulnerable")
}

func TestAnalyze_Corpus(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantVerdict  Verdict
		wantRules    []string // must all be present
		wantNoRules  []string // must all be absent
		wantEvidence bool     // at least one finding must have evidence
	}{
		{
			name:        "safe glob namespace wildcard",
			input:       "MatthiasLohr/*",
			wantVerdict: Safe,
			wantRules:   []string{RuleIDInfo},
			wantNoRules: []string{RuleIDNegationOnlyFilter, RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass, RuleIDLeadingSlashGlob},
		},
		{
			name:        "safe glob with brace expansion",
			input:       `commonground/{nlx,core,don,haven,fsc}/**`,
			wantVerdict: Safe,
			wantRules:   []string{RuleIDInfo},
			wantNoRules: []string{RuleIDNegationOnlyFilter, RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass},
		},
		{
			name:        "safe explicit brace alternatives",
			input:       "myname{a,b}/*",
			wantVerdict: Safe,
			wantRules:   []string{RuleIDInfo},
			wantNoRules: []string{RuleIDNegationOnlyFilter, RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass},
		},
		{
			name:        "safe extglob single alternative",
			input:       "@(myname|other)/*",
			wantVerdict: Safe,
			wantRules:   []string{RuleIDInfo},
			wantNoRules: []string{RuleIDNegationOnlyFilter, RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass},
		},
		{
			name:        "safe literal path",
			input:       "gemseo/dev/gemseo",
			wantVerdict: Safe,
			wantRules:   []string{RuleIDInfo},
			wantNoRules: []string{RuleIDNegationOnlyFilter, RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass, RuleIDLeadingSlashGlob},
		},
		{
			name:        "safe glob hyphen-namespace wildcard",
			input:       "haproxy-haptic/*",
			wantVerdict: Safe,
			wantRules:   []string{RuleIDInfo},
			wantNoRules: []string{RuleIDNegationOnlyFilter, RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass, RuleIDLeadingSlashGlob},
		},
		{
			name:        "safe namespace allowlist with unanchored negative regex exclusions",
			input:       `["${CI_PROJECT_ROOT_NAMESPACE}/**", "!/.*-deletion_scheduled-.*/", "!/.*/forks//", "!/.*renovate-test.*/"]`,
			wantVerdict: Safe,
			wantRules:   []string{RuleIDInfo},
			wantNoRules: []string{RuleIDNegationOnlyFilter, RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass},
		},
		{
			name:         "V4 vulnerable extglob with sibling namespace suffix wildcard",
			input:        "+(myname|myname-renovate|myname-projects)*/*",
			wantVerdict:  Vulnerable,
			wantRules:    []string{RuleIDPathBoundaryBypass, RuleIDInfo},
			wantEvidence: true,
		},
		{
			name:        "N2 broken half-delimited leading slash",
			input:       "/gms-squared/support/**",
			wantVerdict: Broken,
			wantRules:   []string{RuleIDLeadingSlashGlob, RuleIDInfo},
			wantNoRules: []string{RuleIDNegationOnlyFilter, RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass},
		},
		{
			name:         "V3 vulnerable unanchored regex",
			input:        "/myorg/",
			wantVerdict:  Vulnerable,
			wantRules:    []string{RuleIDUnanchoredRegex, RuleIDInfo},
			wantEvidence: true,
		},
		{
			name:         "V4 vulnerable anchored but no separator",
			input:        "/^myorg/",
			wantVerdict:  Vulnerable,
			wantRules:    []string{RuleIDPathBoundaryBypass, RuleIDInfo},
			wantNoRules:  []string{RuleIDUnanchoredRegex},
			wantEvidence: true,
		},
		{
			name:        "safe anchored regex with separator",
			input:       `/^myorg\//`,
			wantVerdict: Safe,
			wantRules:   []string{RuleIDInfo},
			wantNoRules: []string{RuleIDNegationOnlyFilter, RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass},
		},
		{
			name:        "V1 vulnerable only-negation list",
			input:       `["!my-org/old-*"]`,
			wantVerdict: Vulnerable,
			wantRules:   []string{RuleIDNegationOnlyFilter, RuleIDInfo},
			wantNoRules: []string{RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass},
		},
		{
			name:        "V1 JSON5 single-quoted trailing-comma only-negation list",
			input:       `['!gitlab-community/**',]`,
			wantVerdict: Vulnerable,
			wantRules:   []string{RuleIDNegationOnlyFilter, RuleIDInfo},
			wantNoRules: []string{RuleIDUnrestrictedWildcard, RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass},
		},
		{
			name:        "V2 vulnerable bare wildcard",
			input:       "*",
			wantVerdict: Vulnerable,
			wantRules:   []string{RuleIDUnrestrictedWildcard, RuleIDInfo},
			wantNoRules: []string{RuleIDUnanchoredRegex, RuleIDPathBoundaryBypass},
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
	assert.True(t, hasRule(findings, RuleIDInfo))
}

func TestAnalyze_JSONArrayMixedPosNeg_Safe(t *testing.T) {
	findings := Analyze(`["myorg/*", "!myorg/old-*"]`)
	assert.Equal(t, Safe, verdictOf(findings))
}

func TestAnalyze_MalformedRegexFallback(t *testing.T) {
	// Pattern that looks like a regex but uses a lookahead (invalid in RE2).
	findings := Analyze("/(?=myorg)/")
	assert.True(t, hasRule(findings, RuleIDRegexEngineReview), "N4 should fire for RE2-incompatible regex")
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
