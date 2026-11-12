package filter

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	minimatch "github.com/benjaminnkem/minimatch-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeCandidates(t *testing.T) {
	paths := GitLabProjectPathValues{ProjectPath: "acme/runner", ProjectNamespace: "acme", RootNamespace: "acme"}
	for _, test := range []struct {
		name       string
		value      string
		wantMatch  bool
		wantReview bool
	}{
		{name: "scoped glob", value: "acme/**"},
		{name: "unanchored regex", value: "/acme/", wantMatch: true},
		{name: "unanchored project-name regex", value: "/acme$/", wantMatch: true},
		{name: "excluded project-name regex", value: `["/acme$/", "!attacker/**"]`},
		{name: "unanchored multi-segment regex", value: `/acme\/infra/`, wantMatch: true},
		{name: "multi-segment regex excluded by full list", value: `["/acme\\/infra/", "!attacker/**"]`},
		{name: "prefix regex", value: "/^acme/", wantMatch: true},
		{name: "wildcard", value: "*", wantMatch: true},
		{name: "negative only", value: `["!acme/private"]`, wantMatch: true},
		{name: "all candidates excluded", value: `["*", "!/.*/"]`},
		{name: "negative star does not exclude paths", value: `["*", "!*"]`, wantMatch: true},
		{name: "explicit multiple roots", value: `["acme/*", "other/*"]`},
		{name: "excluded attacker root", value: `["*", "!attacker/**"]`, wantMatch: true},
		{name: "resolved variable", value: "${CI_PROJECT_ROOT_NAMESPACE}/**"},
		{name: "unresolved variable", value: "${CUSTOM}/**", wantReview: true},
		{name: "short regex delimiter", value: "/i", wantReview: true},
		{name: "nested negative extglob", value: "@(acme|!(other|else))/*", wantReview: true},
		{name: "nested positive extglob", value: "@(acme|+(other|else))/*", wantReview: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := analyzeCandidates(test.value, paths)
			assert.Equal(t, test.wantMatch, len(result.Evidence) > 0, "%v", result.Evidence)
			assert.Equal(t, test.wantReview, result.Review)
			for _, evidence := range result.Evidence {
				root, _, _ := strings.Cut(evidence, "/")
				assert.NotEqual(t, paths.RootNamespace, root)
				list := filterList{patterns: parsePatterns(test.value)}
				assert.True(t, list.match(evidence), "%s must pass the complete filter", evidence)
			}
		})
	}
}

func TestCandidateProductionEntryPoint(t *testing.T) {
	paths := GitLabProjectPathValues{RootNamespace: "acme"}
	assert.True(t, hasRule(AnalyzeWithGitLabProjectPaths("/acme/", paths), RuleIDUnanchoredRegex))
	assert.False(t, hasRule(AnalyzeWithGitLabProjectPaths(`["*", "!/.*/"]`, paths), RuleIDUnrestrictedWildcard))
	assert.True(t, hasRule(AnalyzeWithGitLabProjectPaths("${CUSTOM}/**", paths), RuleIDUnresolvedVariable))
	assert.Contains(t, analyzeCandidates("/Acme/", GitLabProjectPathValues{RootNamespace: "Acme"}).Evidence, "Acme-evil/project")
	assert.Contains(t, analyzeCandidates("/Other/", GitLabProjectPathValues{RootNamespace: "Acme"}).Evidence, "Other-evil/project")
	assert.Contains(t, analyzeCandidates(`/acme\/infra/`, paths).Evidence, "attacker/acme/infra-test")
	assert.Contains(t, analyzeCandidates(`/acme-org\/infra/`, paths).Evidence, "attacker/acme-org/infra-test")
	assert.Contains(t, analyzeCandidates(`/acme$/`, paths).Evidence, "attacker/acme")
}

func TestCandidateAlphanumericSuffixes(t *testing.T) {
	paths := GitLabProjectPathValues{RootNamespace: "acme"}
	for _, test := range []struct {
		name     string
		pattern  string
		evidence string
	}{
		{name: "regex nonzero digit", pattern: `/^acme[1-9]/`, evidence: "acme1/project"},
		{name: "regex final digit", pattern: `/^acme[9]/`, evidence: "acme9/project"},
		{name: "regex alphabet range", pattern: `/^acme[m-z]/`, evidence: "acmem/project"},
		{name: "glob nonzero digit", pattern: `acme[1-9]/*`, evidence: "acme1/project"},
		{name: "glob final letter", pattern: `acme[z]/*`, evidence: "acmez/project"},
		{name: "negative pattern excludes first digit", pattern: `["/^acme[1-9]/", "!acme1/*"]`, evidence: "acme2/project"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := analyzeCandidates(test.pattern, paths)
			require.Contains(t, result.Evidence, test.evidence)
			assert.True(t, (&filterList{patterns: parsePatterns(test.pattern)}).match(test.evidence))
			assert.False(t, result.Review)
		})
	}
	assert.Empty(t, analyzeCandidates(`["/^acme[1-9]/", "!acme[1-9]/*"]`, paths).Evidence)
	for _, suffix := range "abcdefghijklmnopqrstuvwxyz0123456789" {
		pattern := "/^acme[" + string(suffix) + "]/"
		expected := "acme" + string(suffix) + "/project"
		assert.Contains(t, analyzeCandidates(pattern, paths).Evidence, expected, pattern)
	}
}

func TestMinimatchNodeParity(t *testing.T) {
	node := os.Getenv("PIPELEEK_MINIMATCH_NODE")
	module := os.Getenv("PIPELEEK_MINIMATCH_NODE_MODULE")
	if node == "" || module == "" {
		t.Skip("set PIPELEEK_MINIMATCH_NODE and PIPELEEK_MINIMATCH_NODE_MODULE for the JavaScript oracle")
	}
	type matchCase struct {
		Pattern string `json:"pattern"`
		Path    string `json:"path"`
	}
	var cases []matchCase
	for _, pattern := range []string{
		"*", "!*", "**", "!**", "acme/**", "acme/*", "acme/?", "acme/[a-z]*",
		"acme/{app,bot}/**", "@(acme|other)/*", "+(acme|other)*/*",
		"?(acme|other)*/*", "*(acme|other)*/*", "!acme/private*",
		"ACME/**", "#comment", "acme/.*", "acme/{app,bot}", "acme[1-9]/*", "acme[m-z]/*", "acme[z]/*",
	} {
		for _, path := range []string{
			"acme/project", "acme/.hidden", "acme/app/x", "acme/bot", "acme/A",
			"acme/private-repo", "acmeevil/project", "other/project", "otherelse/project",
			"attacker/acme/project", "ACME/project", ".hidden/project", "acme", "acme/", "acme1/project", "acme0/project", "acmez/project",
		} {
			cases = append(cases, matchCase{Pattern: pattern, Path: path})
		}
	}
	input, err := json.Marshal(cases)
	require.NoError(t, err)
	const script = `const fs=require('fs'); const {Minimatch}=require(process.argv[1]); const cases=JSON.parse(fs.readFileSync(0,'utf8')); process.stdout.write(JSON.stringify(cases.map(({pattern,path}) => pattern === '*' || new Minimatch(pattern,{dot:true,nocase:true}).match(path))));`
	command := exec.Command(node, "-e", script, module)
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	require.NoError(t, err)
	var expected []bool
	require.NoError(t, json.Unmarshal(output, &expected))
	require.Len(t, expected, len(cases))
	for index, test := range cases {
		matcher, err := minimatch.NewMinimatch(test.Pattern, minimatch.Options{Dot: true, NoCase: true, Platform: "linux"})
		require.NoError(t, err)
		assert.Equal(t, expected[index], test.Pattern == "*" || matcher.Match(test.Path), "pattern=%q path=%q", test.Pattern, test.Path)
		list := filterList{patterns: []parsedPattern{classifyPattern(test.Pattern)}}
		assert.Equal(t, expected[index], list.match(test.Path), "list pattern=%q path=%q", test.Pattern, test.Path)
	}
}

func TestCandidateEvidenceNodeOracle(t *testing.T) {
	node := os.Getenv("PIPELEEK_MINIMATCH_NODE")
	module := os.Getenv("PIPELEEK_MINIMATCH_NODE_MODULE")
	if node == "" || module == "" {
		t.Skip("set PIPELEEK_MINIMATCH_NODE and PIPELEEK_MINIMATCH_NODE_MODULE for the JavaScript oracle")
	}
	type oracleCase struct {
		Patterns  []string `json:"patterns"`
		Candidate string   `json:"candidate"`
	}
	var cases []oracleCase
	paths := GitLabProjectPathValues{RootNamespace: "acme"}
	for _, patterns := range [][]string{
		{`/^acme[1-9]/`}, {`/^acme[m-z]/`}, {`/^acme[9]/`},
		{"acme[1-9]/*"}, {"acme[m-z]/*"}, {"acme[z]/*"},
		{`/^acme[1-9]/`, "!acme1/*"}, {"*", "!attacker/**"},
		{`/acme\/infra/`}, {`/acme$/`}, {"+(acme|other)*/*"},
	} {
		encoded, err := json.Marshal(patterns)
		require.NoError(t, err)
		result := analyzeCandidates(string(encoded), paths)
		require.NotEmpty(t, result.Evidence, "%v", patterns)
		for _, candidate := range result.Evidence {
			cases = append(cases, oracleCase{Patterns: patterns, Candidate: candidate})
		}
	}
	input, err := json.Marshal(cases)
	require.NoError(t, err)
	const script = `const fs=require('fs'); const {Minimatch}=require(process.argv[1]); const cases=JSON.parse(fs.readFileSync(0,'utf8')); const match=(value,pattern)=>{const neg=pattern.startsWith('!'); const body=neg?pattern.slice(1):pattern; if(/^\/.+\/i?$/.test(body)){const insensitive=body.endsWith('/i'); const source=body.slice(1,insensitive?-2:-1); const found=new RegExp(source,insensitive?'i':'').test(value); return neg?!found:found} return pattern==='*'||new Minimatch(pattern,{dot:true,nocase:true}).match(value)}; process.stdout.write(JSON.stringify(cases.map(({patterns,candidate})=>{const positive=patterns.filter(p=>!p.startsWith('!')); return (!positive.length||positive.some(p=>match(candidate,p)))&&patterns.filter(p=>p.startsWith('!')).every(p=>match(candidate,p))})));`
	command := exec.Command(node, "-e", script, module)
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	require.NoError(t, err)
	var matched []bool
	require.NoError(t, json.Unmarshal(output, &matched))
	require.Len(t, matched, len(cases))
	for index, test := range cases {
		assert.True(t, matched[index], "patterns=%v candidate=%q", test.Patterns, test.Candidate)
	}
}
