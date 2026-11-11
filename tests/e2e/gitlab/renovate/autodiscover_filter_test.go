//go:build e2e

package e2e

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type autodiscoverFilterSource struct {
	name       string
	filePath   string
	fileType   string
	ciMode     string
	extraFiles map[string]string
}

type autodiscoverFilterExpectation struct {
	name          string
	value         string
	rule          string
	reviewRule    string
	skipForEnvCLI bool
}

var ansiEscapeSequence = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestGLRenovateAutodiscoverFilterSources(t *testing.T) {
	filters := []autodiscoverFilterExpectation{
		{name: "negation-only filter", value: "!my-org/old-*", rule: "negation-only-filter"},
		{name: "bare wildcard", value: "*", rule: "unrestricted-wildcard"},
		{name: "unanchored regex", value: "/myname/", rule: "unanchored-regex"},
		{name: "anchored regex without namespace boundary", value: "/^myname/", rule: "path-boundary-bypass"},
		{name: "extglob sibling suffix", value: "+(myname|myname-renovate|myname-projects)*/*", rule: "path-boundary-bypass"},
		{name: "extglob plus repetition", value: "+(myname|other)/*", rule: "path-boundary-bypass"},
		{name: "extglob at with suffix wildcard", value: "@(myname|other)*/*", rule: "path-boundary-bypass"},
		{name: "extglob optional with suffix wildcard", value: "?(myname|other)*/*", rule: "path-boundary-bypass"},
		{name: "extglob zero-or-more with suffix wildcard", value: "*(myname|other)*/*", rule: "path-boundary-bypass"},
		{name: "nested extglob review", value: "@(myname|+(other|else))/*", reviewRule: "unsupported-extglob"},
		{name: "regex quantified character class", value: "/^myname[0-9]+/", rule: "path-boundary-bypass"},
		{name: "regex alternatives without boundaries", value: "/^myname|^othername/", rule: "path-boundary-bypass"},
		{name: "resolved root namespace suffix wildcard", value: "$CI_PROJECT_ROOT_NAMESPACE*/*", rule: "path-boundary-bypass"},
		{name: "resolved project namespace suffix wildcard", value: "$CI_PROJECT_NAMESPACE*/*", rule: "path-boundary-bypass"},
		{name: "resolved project path suffix wildcard", value: "$CI_PROJECT_PATH*/*", rule: "path-boundary-bypass"},
		{name: "unresolved custom project variable review", value: "${RENOVATE_PROJECT}", reviewRule: "unresolved-variable"},
		{name: "glob single-character wildcard", value: "myname?/*", rule: "path-boundary-bypass"},
		{name: "glob character class", value: "myname[0-9]/*", rule: "path-boundary-bypass"},
		{name: "glob brace alternatives with suffix wildcard", value: "myname{a,b}*/*", rule: "path-boundary-bypass", skipForEnvCLI: true},
	}

	sources := []autodiscoverFilterSource{
		{name: "ci yaml RENOVATE_EXTRA_FLAGS", ciMode: "extra-flags"},
		{name: "ci yaml RENOVATE_AUTODISCOVER_FILTER", ciMode: "env-filter"},
		{name: "ci yaml command-line flag", ciMode: "script-flag"},
		{name: "renovate.json", filePath: "renovate.json", fileType: "json"},
		{name: "renovate.json5", filePath: "renovate.json5", fileType: "json5"},
		{name: ".github/renovate.json", filePath: ".github/renovate.json", fileType: "json"},
		{name: ".github/renovate.json5", filePath: ".github/renovate.json5", fileType: "json5"},
		{name: ".gitlab/renovate.json", filePath: ".gitlab/renovate.json", fileType: "json"},
		{name: ".gitlab/renovate.json5", filePath: ".gitlab/renovate.json5", fileType: "json5"},
		{name: ".renovaterc", filePath: ".renovaterc", fileType: "key-value"},
		{name: ".renovaterc.json", filePath: ".renovaterc.json", fileType: "json"},
		{name: ".renovaterc.json5", filePath: ".renovaterc.json5", fileType: "json5"},
		{name: "config.js", filePath: "config.js", fileType: "javascript"},
	}

	selfHostedProxy := setupMockSelfHostedOptionsProxy(t)
	for _, source := range sources {
		t.Run(source.name, func(t *testing.T) {
			apiURL, requestedFiles := setupMockGitLabAutodiscoverFilterAPI(t, source, filters)
			args := []string{"gl", "renovate", "enum", "--url", apiURL, "--token", "mock-token"}
			if source.filePath == "" {
				args = append(args, "--fast")
			}

			env := []string{
				"HTTP_PROXY=" + selfHostedProxy,
				"HTTPS_PROXY=" + selfHostedProxy,
				"http_proxy=" + selfHostedProxy,
				"https_proxy=" + selfHostedProxy,
				"NO_PROXY=127.0.0.1,localhost",
				"no_proxy=127.0.0.1,localhost",
				"FORCE_COLOR=0",
				"NO_COLOR=1",
			}
			stdout, stderr, exitErr := testutil.RunCLI(t, args, env, 2*time.Minute)
			require.NoError(t, exitErr, "enum failed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)

			for _, filter := range filters {
				if source.ciMode != "" && filter.skipForEnvCLI {
					continue
				}
				assertFilterFinding(t, stdout+"\n"+stderr, filter)
			}
			assert.Contains(t, stdout+"\n"+stderr, "isSelfHosted=true")
			if source.filePath != "" {
				assert.Contains(t, requestedFiles(), source.filePath, "enum did not fetch the configured Renovate file")
			}
		})
	}
}

func TestGLRenovateCommaDelimitedFilters(t *testing.T) {
	sources := []autodiscoverFilterSource{
		{name: "RENOVATE_AUTODISCOVER_FILTER", ciMode: "env-filter"},
		{name: "RENOVATE_EXTRA_FLAGS", ciMode: "extra-flags"},
		{name: "command-line flag", ciMode: "script-flag"},
	}
	selfHostedProxy := setupMockSelfHostedOptionsProxy(t)
	for _, source := range sources {
		t.Run(source.name, func(t *testing.T) {
			filter := autodiscoverFilterExpectation{
				name:  source.name + " with comma-delimited wildcard",
				value: "branchbooks/*,*",
				rule:  "unrestricted-wildcard",
			}
			apiURL, _ := setupMockGitLabAutodiscoverFilterAPI(t, source, []autodiscoverFilterExpectation{filter})
			stdout, stderr, exitErr := testutil.RunCLI(t, []string{
				"gl", "renovate", "enum", "--url", apiURL, "--token", "mock-token", "--fast",
			}, []string{
				"HTTP_PROXY=" + selfHostedProxy,
				"HTTPS_PROXY=" + selfHostedProxy,
				"http_proxy=" + selfHostedProxy,
				"https_proxy=" + selfHostedProxy,
				"NO_PROXY=127.0.0.1,localhost",
				"no_proxy=127.0.0.1,localhost",
				"FORCE_COLOR=0",
				"NO_COLOR=1",
			}, 2*time.Minute)
			require.NoError(t, exitErr, "enum failed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
			assertFilterFinding(t, stdout+"\n"+stderr, filter)
		})
	}
}

func TestGLRenovateConfigJSFilterWhenRenovateJSONExists(t *testing.T) {
	source := autodiscoverFilterSource{
		name:     "renovate.json plus config.js",
		filePath: "renovate.json",
		fileType: "json",
		extraFiles: map[string]string{
			"config.js": `module.exports = { autodiscover: true, autodiscoverFilter: ["release-process/**"] };`,
		},
	}
	apiURL, requestedFiles := setupMockGitLabAutodiscoverFilterAPI(t, source, []autodiscoverFilterExpectation{{name: "coexisting config files"}})
	selfHostedProxy := setupMockSelfHostedOptionsProxy(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "enum", "--url", apiURL, "--token", "mock-token",
	}, []string{
		"HTTP_PROXY=" + selfHostedProxy,
		"HTTPS_PROXY=" + selfHostedProxy,
		"http_proxy=" + selfHostedProxy,
		"https_proxy=" + selfHostedProxy,
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
		"FORCE_COLOR=0",
		"NO_COLOR=1",
	}, 2*time.Minute)
	require.NoError(t, exitErr, "enum failed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	output := ansiEscapeSequence.ReplaceAllString(stdout+"\n"+stderr, "")
	assert.Contains(t, output, "Renovate configuration")
	assert.Contains(t, output, "hasAutodiscovery=true")
	assert.Contains(t, output, "autodiscoverFilter")
	assert.Contains(t, output, "release-process/**")
	assert.NotContains(t, output, "hasConfigFile=")
	assert.NotContains(t, output, "hasAutodiscoveryFilters=")
	assert.Contains(t, output, "isSelfHosted=true")
	assert.NotContains(t, output, "autodiscoveryFilterBypass=unfiltered-autodiscovery")
	assert.Contains(t, requestedFiles(), "renovate.json")
	assert.Contains(t, requestedFiles(), "config.js")
}

func TestGLRenovateConfigJSJSON5NegativeArray(t *testing.T) {
	filter := autodiscoverFilterExpectation{
		name:  "single-quoted negative-only filter",
		value: `['!gitlab-community/**',]`,
		rule:  "negation-only-filter",
	}
	source := autodiscoverFilterSource{name: "JSON5-style config.js filter", filePath: "config.js", fileType: "javascript-array"}
	apiURL, _ := setupMockGitLabAutodiscoverFilterAPI(t, source, []autodiscoverFilterExpectation{filter})
	selfHostedProxy := setupMockSelfHostedOptionsProxy(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "enum", "--url", apiURL, "--token", "mock-token",
	}, []string{
		"HTTP_PROXY=" + selfHostedProxy,
		"HTTPS_PROXY=" + selfHostedProxy,
		"http_proxy=" + selfHostedProxy,
		"https_proxy=" + selfHostedProxy,
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
		"FORCE_COLOR=0",
		"NO_COLOR=1",
	}, 2*time.Minute)
	require.NoError(t, exitErr, "enum failed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	assertFilterFinding(t, stdout+"\n"+stderr, filter)
}

func TestGLRenovateNonFilterScopesAreNotAnalyzed(t *testing.T) {
	scopes := []struct {
		name       string
		fileType   string
		key        string
		value      string
		wantBypass bool
	}{
		{name: "namespaces", fileType: "javascript-namespaces", key: "autodiscoverNamespaces", value: `["gitlab-com/gl-infra"]`},
		{name: "topics", fileType: "javascript-topics", key: "autodiscoverTopics", value: `["renovate-managed"]`},
		{name: "projects unsupported on GitLab", fileType: "javascript-projects", key: "autodiscoverProjects", value: `["project"]`, wantBypass: true},
		{name: "empty namespaces", fileType: "javascript-namespaces", key: "autodiscoverNamespaces", value: `[]`, wantBypass: true},
		{name: "empty topics", fileType: "javascript-topics", key: "autodiscoverTopics", value: `[]`, wantBypass: true},
	}
	for _, scope := range scopes {
		t.Run(scope.name, func(t *testing.T) {
			source := autodiscoverFilterSource{name: scope.name, filePath: "config.js", fileType: scope.fileType}
			apiURL, _ := setupMockGitLabAutodiscoverFilterAPI(t, source, []autodiscoverFilterExpectation{{name: scope.name, value: scope.value}})
			selfHostedProxy := setupMockSelfHostedOptionsProxy(t)
			stdout, stderr, exitErr := testutil.RunCLI(t, []string{
				"gl", "renovate", "enum", "--url", apiURL, "--token", "mock-token",
			}, []string{
				"HTTP_PROXY=" + selfHostedProxy,
				"HTTPS_PROXY=" + selfHostedProxy,
				"http_proxy=" + selfHostedProxy,
				"https_proxy=" + selfHostedProxy,
				"NO_PROXY=127.0.0.1,localhost",
				"no_proxy=127.0.0.1,localhost",
				"FORCE_COLOR=0",
				"NO_COLOR=1",
			}, 2*time.Minute)
			require.NoError(t, exitErr, "enum failed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
			output := ansiEscapeSequence.ReplaceAllString(stdout+"\n"+stderr, "")
			assert.Contains(t, output, "autodiscoveryFilterType="+scope.key)
			if scope.wantBypass {
				assert.Contains(t, output, "autodiscoveryFilterBypass=unfiltered-autodiscovery")
			} else {
				assert.NotContains(t, output, "autodiscoveryFilterBypass=")
				assert.NotContains(t, output, "autodiscoveryFilterReview=")
			}
		})
	}
}

func TestGLRenovateAutodiscoveryWithoutScopeIsVulnerable(t *testing.T) {
	source := autodiscoverFilterSource{name: "unfiltered CI autodiscovery", ciMode: "no-filter"}
	apiURL, _ := setupMockGitLabAutodiscoverFilterAPI(t, source, []autodiscoverFilterExpectation{{name: "unfiltered"}})
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "enum", "--url", apiURL, "--token", "mock-token", "--fast",
	}, []string{"FORCE_COLOR=0", "NO_COLOR=1"}, 2*time.Minute)
	require.NoError(t, exitErr, "enum failed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	output := ansiEscapeSequence.ReplaceAllString(stdout+"\n"+stderr, "")
	assert.Contains(t, output, "hasAutodiscovery=true")
	assert.NotContains(t, output, "hasAutodiscoveryFilters=")
	assert.NotContains(t, output, "hasConfigFile=")
	assert.Contains(t, output, "autodiscoveryFilterBypass=unfiltered-autodiscovery")
}

func TestGLRenovateEmptyFilterIsVulnerable(t *testing.T) {
	source := autodiscoverFilterSource{name: "empty CI filter", ciMode: "empty-filter"}
	apiURL, _ := setupMockGitLabAutodiscoverFilterAPI(t, source, []autodiscoverFilterExpectation{{name: "empty filter"}})
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "enum", "--url", apiURL, "--token", "mock-token", "--fast",
	}, []string{"FORCE_COLOR=0", "NO_COLOR=1"}, 2*time.Minute)
	require.NoError(t, exitErr, "enum failed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	output := ansiEscapeSequence.ReplaceAllString(stdout+"\n"+stderr, "")
	assert.Contains(t, output, "hasAutodiscovery=true")
	assert.NotContains(t, output, "hasAutodiscoveryFilters=")
	assert.NotContains(t, output, "hasConfigFile=")
	assert.Contains(t, output, "autodiscoveryFilterValue=")
	assert.Contains(t, output, "autodiscoveryFilterBypass=unfiltered-autodiscovery")
}

func TestGLRenovateDisabledAutodiscoveryIsNotVulnerable(t *testing.T) {
	source := autodiscoverFilterSource{name: "disabled CI autodiscovery", ciMode: "disabled"}
	apiURL, _ := setupMockGitLabAutodiscoverFilterAPI(t, source, []autodiscoverFilterExpectation{{name: "disabled"}})
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "enum", "--url", apiURL, "--token", "mock-token", "--fast",
	}, []string{"FORCE_COLOR=0", "NO_COLOR=1"}, 2*time.Minute)
	require.NoError(t, exitErr, "enum failed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	output := ansiEscapeSequence.ReplaceAllString(stdout+"\n"+stderr, "")
	assert.Contains(t, output, "hasAutodiscovery=false")
	assert.NotContains(t, output, "autodiscoveryFilterBypass=unfiltered-autodiscovery")
}

func TestGLRenovateConfigDisablesAutodiscovery(t *testing.T) {
	source := autodiscoverFilterSource{name: "config.js disables autodiscovery", filePath: "config.js", fileType: "javascript-disabled", ciMode: "no-autodiscovery"}
	apiURL, _ := setupMockGitLabAutodiscoverFilterAPI(t, source, []autodiscoverFilterExpectation{{name: "disabled config"}})
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "enum", "--url", apiURL, "--token", "mock-token",
	}, []string{"FORCE_COLOR=0", "NO_COLOR=1"}, 2*time.Minute)
	require.NoError(t, exitErr, "enum failed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	output := ansiEscapeSequence.ReplaceAllString(stdout+"\n"+stderr, "")
	assert.Contains(t, output, "hasAutodiscovery=false")
	assert.NotContains(t, output, "autodiscoveryFilterBypass=unfiltered-autodiscovery")
}

func assertFilterFinding(t *testing.T, output string, filter autodiscoverFilterExpectation) {
	t.Helper()
	output = ansiEscapeSequence.ReplaceAllString(output, "")
	for _, line := range strings.Split(output, "\n") {
		if filter.rule != "" && strings.Contains(line, "autodiscoveryFilterBypass="+filter.rule) &&
			strings.Contains(line, "autodiscoveryFilterValue="+filter.value) {
			return
		}
		if filter.reviewRule != "" && strings.Contains(line, "autodiscoveryFilterReview="+filter.reviewRule) &&
			strings.Contains(line, "autodiscoveryFilterValue="+filter.value) {
			return
		}
	}
	t.Fatalf("expected CLI output to report filter %q with bypass rule %s or review rule %s\noutput:\n%s", filter.value, filter.rule, filter.reviewRule, output)
}

func setupMockGitLabAutodiscoverFilterAPI(t *testing.T, source autodiscoverFilterSource, filters []autodiscoverFilterExpectation) (string, func() []string) {
	t.Helper()
	filterByProjectID := make(map[int64]autodiscoverFilterExpectation, len(filters))
	projectByID := make(map[int64]map[string]any, len(filters))
	for i, filter := range filters {
		id := int64(1000 + i)
		filterByProjectID[id] = filter
		projectByID[id] = map[string]any{
			"id":                      id,
			"name":                    fmt.Sprintf("filter-%d", i),
			"path":                    fmt.Sprintf("filter-%d", i),
			"path_with_namespace":     fmt.Sprintf("group/subgroup/filter-%d", i),
			"namespace":               map[string]any{"id": 2000, "name": "subgroup", "path": "subgroup", "kind": "group", "full_path": "group/subgroup"},
			"web_url":                 fmt.Sprintf("https://gitlab.example/group/subgroup/filter-%d", i),
			"default_branch":          "main",
			"builds_access_level":     "enabled",
			"repository_access_level": "enabled",
		}
	}

	var mu sync.Mutex
	var filesRequested []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, _ *http.Request) {
		projects := make([]map[string]any, 0, len(projectByID))
		for _, project := range projectByID {
			projects = append(projects, project)
		}
		writeJSON(t, w, http.StatusOK, projects)
	})
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v4/projects/")
		projectIDText, endpoint, ok := strings.Cut(rest, "/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		var projectID int64
		if _, err := fmt.Sscan(projectIDText, &projectID); err != nil {
			http.NotFound(w, r)
			return
		}
		filter, exists := filterByProjectID[projectID]
		if !exists {
			http.NotFound(w, r)
			return
		}

		if strings.HasPrefix(endpoint, "ci/lint") {
			mergedYAML := `image: renovate/renovate:44` + "\n"
			if source.filePath == "" {
				mergedYAML = ciYAMLForFilter(source.ciMode, filter.value)
			} else if source.ciMode != "no-autodiscovery" {
				mergedYAML += "variables:\n  RENOVATE_AUTODISCOVER: \"true\"\n"
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"valid":       true,
				"merged_yaml": mergedYAML,
				"errors":      []string{},
				"warnings":    []string{},
			})
			return
		}

		const filesPrefix = "repository/files/"
		if strings.HasPrefix(endpoint, filesPrefix) && r.Method == http.MethodGet {
			filePath := strings.TrimPrefix(endpoint, filesPrefix)
			mu.Lock()
			filesRequested = append(filesRequested, filePath)
			mu.Unlock()
			content := ""
			if filePath == source.filePath && source.filePath != "" {
				content = renovateFilterConfigContent(source.fileType, filter.value)
			} else if extraContent, ok := source.extraFiles[filePath]; ok {
				content = extraContent
			} else {
				http.NotFound(w, r)
				return
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"file_name": filepath.Base(filePath),
				"file_path": filePath,
				"size":      len(content),
				"encoding":  "base64",
				"content":   base64.StdEncoding.EncodeToString([]byte(content)),
				"ref":       "main",
			})
			return
		}
		http.NotFound(w, r)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), filesRequested...)
	}
}

func ciYAMLForFilter(mode, filterValue string) string {
	switch mode {
	case "extra-flags":
		return "image: renovate/renovate:44\nvariables:\n  RENOVATE_EXTRA_FLAGS: \"--autodiscover-filter=" + filterValue + "\"\n"
	case "env-filter":
		return "image: renovate/renovate:44\nvariables:\n  RENOVATE_AUTODISCOVER_FILTER: '" + filterValue + "'\n"
	case "script-flag":
		return "image: renovate/renovate:44\nscript:\n  - \"renovate --autodiscover-filter='" + filterValue + "'\"\n"
	case "no-filter":
		return "image: renovate/renovate:44\nvariables:\n  RENOVATE_AUTODISCOVER: 'true'\n"
	case "disabled":
		return "image: renovate/renovate:44\nvariables:\n  RENOVATE_AUTODISCOVER: 'false'\n"
	case "empty-filter":
		return "image: renovate/renovate:44\nvariables:\n  RENOVATE_AUTODISCOVER: 'true'\n  RENOVATE_AUTODISCOVER_FILTER: ''\n"
	default:
		panic("unknown CI filter source: " + mode)
	}
}

func renovateFilterConfigContent(fileType, filterValue string) string {
	quoted, _ := json.Marshal(filterValue)
	switch fileType {
	case "json":
		return `{"autodiscover":true,"autodiscoverFilter":` + string(quoted) + `}`
	case "json5":
		return `{ autodiscover: true, autodiscoverFilter: ` + string(quoted) + `, }`
	case "key-value":
		return "autodiscover=true\nautodiscoverFilter: '" + filterValue + "'\n"
	case "javascript":
		return "module.exports = { autodiscover: true, autodiscoverFilter: " + string(quoted) + " };\n"
	case "javascript-disabled":
		return "module.exports = { autodiscover: false };\n"
	case "javascript-array":
		return "module.exports = { autodiscover: true, autodiscoverFilter: " + filterValue + " };\n"
	case "javascript-namespaces":
		return "module.exports = { autodiscover: true, autodiscoverNamespaces: " + filterValue + " };\n"
	case "javascript-projects":
		return "module.exports = { autodiscover: true, autodiscoverProjects: " + filterValue + " };\n"
	case "javascript-topics":
		return "module.exports = { autodiscover: true, autodiscoverTopics: " + filterValue + " };\n"
	default:
		panic("unknown Renovate config type: " + fileType)
	}
}

func setupMockSelfHostedOptionsProxy(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "raw.githubusercontent.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"raw.githubusercontent.com"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(
		pemEncode("CERTIFICATE", certificateDER),
		pemEncodeECPrivateKey(privateKey),
	)
	require.NoError(t, err)

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "raw.githubusercontent.com:443" {
			http.Error(w, "unexpected proxy request", http.StatusBadRequest)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		connection, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}

		tlsConnection := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}})
		defer tlsConnection.Close()
		if err := tlsConnection.Handshake(); err != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(tlsConnection))
		if err != nil {
			return
		}
		defer request.Body.Close()
		body := "## `selfHostedType`\n## `autodiscoverFilter`\n"
		_, _ = fmt.Fprintf(tlsConnection, "HTTP/1.1 200 OK\r\nContent-Type: text/markdown\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}))
	t.Cleanup(proxy.Close)
	return proxy.URL
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	require.NoError(t, json.NewEncoder(w).Encode(value))
}

func pemEncode(blockType string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data})
}

func pemEncodeECPrivateKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pemEncode("EC PRIVATE KEY", der)
}
