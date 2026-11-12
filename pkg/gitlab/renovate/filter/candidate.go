package filter

import (
	"strings"

	minimatch "github.com/benjaminnkem/minimatch-go"
)

type candidateResult struct {
	Evidence   []string
	RuleID     string
	Pattern    string
	Review     bool
	ReviewRule string
}

func analyzeCandidates(filterValue string, paths GitLabProjectPathValues) candidateResult {
	variables := map[string]string{
		"CI_PROJECT_ROOT_NAMESPACE": paths.RootNamespace,
		"CI_PROJECT_NAMESPACE":      paths.ProjectNamespace,
		"CI_PROJECT_PATH":           paths.ProjectPath,
	}
	resolved := reEnvironmentVariable.ReplaceAllStringFunc(filterValue, func(token string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(token, "${"), "}")
		if !strings.HasPrefix(token, "${") {
			name = token[1:]
		}
		if value := variables[name]; value != "" {
			return value
		}
		return token
	})
	allPatterns := parsePatterns(resolved)
	var patterns []parsedPattern
	unresolved := false
	for _, pattern := range allPatterns {
		if reEnvironmentVariable.MatchString(pattern.raw) {
			unresolved = true
			if pattern.negated || strings.HasPrefix(pattern.raw, "$") {
				return candidateResult{Review: true, ReviewRule: RuleIDUnresolvedVariable}
			}
			continue
		}
		patterns = append(patterns, pattern)
	}
	if unresolved {
		positive, _ := splitPosNeg(patterns)
		if len(positive) == 0 {
			return candidateResult{Review: true, ReviewRule: RuleIDUnresolvedVariable}
		}
	}
	if len(patterns) == 0 {
		return candidateResult{}
	}
	for _, pattern := range patterns {
		if pattern.kind == KindMalformedRegexFallback {
			return candidateResult{Review: true, ReviewRule: RuleIDRegexEngineReview}
		}
		if strings.Contains(pattern.raw, "!(") {
			return candidateResult{Review: true, ReviewRule: RuleIDUnsupportedExtglob}
		}
		if strings.Contains(pattern.raw, "(") {
			if _, ok := parseNamespaceExtglob(pattern.raw); pattern.kind == KindGlob && !ok && strings.ContainsAny(pattern.raw, "@+?*") {
				return candidateResult{Review: true, ReviewRule: RuleIDUnsupportedExtglob}
			}
		}
		if pattern.matchErr != nil {
			return candidateResult{Review: true, ReviewRule: RuleIDUnsupportedExtglob}
		}
	}

	trustedRoots := map[string]bool{}
	var roots []string
	var candidates []string
	addRoot := func(root string, trusted bool) {
		if root == "" {
			return
		}
		roots = append(roots, root)
		if trusted {
			trustedRoots[strings.ToLower(root)] = true
		}
	}
	addRoot(paths.RootNamespace, true)
	for _, pattern := range patterns {
		if pattern.negated {
			continue
		}
		if extglob, ok := parseNamespaceExtglob(pattern.raw); ok {
			for _, alternative := range extglob.alternatives {
				addRoot(alternative, true)
				if extglob.operator == '+' || extglob.operator == '*' {
					for _, second := range extglob.alternatives {
						candidates = append(candidates, alternative+second+"/project")
					}
				}
			}
			continue
		}
		alternatives := []string{pattern.raw}
		if pattern.kind == KindGlob {
			if expanded, err := minimatch.BraceExpand(pattern.raw, minimatch.Options{}); err == nil {
				alternatives = expanded
			}
		}
		for _, alternative := range alternatives {
			prefix := alternative
			if pattern.kind == KindRegex {
				prefix = stripRegexBody(pattern.body)
			}
			prefix = scanLiteralPrefix(prefix, pattern.kind == KindRegex)
			root, _, hasSlash := strings.Cut(prefix, "/")
			addRoot(root, hasSlash)
		}
	}

	candidates = append(candidates, "attacker/project", "attacker2/project")
	for _, root := range roots {
		candidates = append(candidates,
			root+"-evil/project", root+"evil/project", root+"a/project", root+"0/project",
			"evil-"+root+"/project", "attacker/"+root+"/project")
	}
	result := candidateResult{Review: unresolved}
	if unresolved {
		result.ReviewRule = RuleIDUnresolvedVariable
	}
	list := filterList{patterns: patterns}
	positive, _ := splitPosNeg(patterns)
	seen := map[string]bool{}
	for _, candidate := range candidates {
		root, _, _ := strings.Cut(candidate, "/")
		if trustedRoots[strings.ToLower(root)] || seen[candidate] || !validGitLabProbePath(candidate) {
			continue
		}
		seen[candidate] = true
		if !list.match(candidate) {
			continue
		}
		result.Evidence = append(result.Evidence, candidate)
		if result.RuleID != "" {
			continue
		}
		if len(positive) == 0 {
			result.RuleID = RuleIDNegationOnlyFilter
			continue
		}
		for _, pattern := range positive {
			if pattern.matchFn(candidate) {
				result.Pattern = pattern.raw
				result.RuleID = RuleIDPathBoundaryBypass
				if pattern.raw == "*" || pattern.kind == KindRegex && pattern.body == ".*" {
					result.RuleID = RuleIDUnrestrictedWildcard
				} else if pattern.kind == KindRegex && !isStartAnchored(pattern.body) {
					result.RuleID = RuleIDUnanchoredRegex
				}
				break
			}
		}
	}
	return result
}
