package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const awsSnippetContent = "[default]\naws_access_key_id = AKIAT4GVSAXXEK64O6KD\naws_secret_access_key = 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\n"

func TestGitLabSnippetsScan_PublicSnippets(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v4/snippets/public" || (r.URL.Path == "/api/v4/snippets" && strings.Contains(r.URL.RawQuery, "scope=public")) || r.URL.Path == "/api/v4/snippets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":      900,
				"title":   "public snippet",
				"web_url": "http://" + r.Host + "/-/snippets/900",
				"files": []map[string]any{{
					"path":    "canary_aws",
					"raw_url": "http://" + r.Host + "/-/snippets/900/raw/main/canary_aws",
				}},
			}})
		case r.URL.Path == "/api/v4/snippets/900/files/main/canary_aws/raw", r.URL.Path == "/api/v4/snippets/900/raw":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(awsSnippetContent))
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "snippets", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--json",
	}, nil, 45*time.Second)

	require.NoError(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, `"snippetId":"900"`)
	assert.Contains(t, output, `"file":"canary_aws"`)

	requests := getRequests()
	var listedPublic, fetchedFile bool
	for _, req := range requests {
		if req.Path == "/api/v4/snippets/public" || req.Path == "/api/v4/snippets" {
			listedPublic = true
			testutil.AssertRequestHeader(t, req, "Private-Token", "glpat-test-token")
		}
		if req.Path == "/api/v4/snippets/900/files/main/canary_aws/raw" || req.Path == "/api/v4/snippets/900/raw" {
			fetchedFile = true
		}
	}
	assert.True(t, listedPublic, "should list public snippets")
	assert.True(t, fetchedFile, "should fetch public snippet file content")
}

func TestGitLabSnippetsScan_MemberFilter(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":                  101,
				"name":                "project",
				"path_with_namespace": "group/project",
			}})
		case "/api/v4/projects/101/snippets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":      901,
				"title":   "member snippet",
				"web_url": "http://" + r.Host + "/group/project/-/snippets/901",
				"files": []map[string]any{{
					"path":    "canary_aws",
					"raw_url": "http://" + r.Host + "/group/project/-/snippets/901/raw/main/canary_aws",
				}},
			}})
		case "/api/v4/projects/101/snippets/901/files/main/canary_aws/raw":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(awsSnippetContent))
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "snippets", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--member",
		"--json",
	}, nil, 20*time.Second)

	require.NoError(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, `"project":"group/project"`)
	assert.Contains(t, output, `"snippetId":"901"`)

	requests := getRequests()
	var projectsListed, snippetsListed bool
	for _, req := range requests {
		if req.Path == "/api/v4/projects" {
			projectsListed = true
			assert.Contains(t, req.RawQuery, "membership=true")
		}
		if req.Path == "/api/v4/projects/101/snippets" {
			snippetsListed = true
		}
	}
	assert.True(t, projectsListed, "should list member projects")
	assert.True(t, snippetsListed, "should list project snippets")
}

func TestGitLabSnippetsScan_ProjectFilter(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects/group%2Fproject", "/api/v4/projects/group/project":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":                  303,
				"name":                "project",
				"path_with_namespace": "group/project",
			})
		case "/api/v4/projects/303/snippets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":      903,
				"title":   "project snippet",
				"web_url": "http://" + r.Host + "/group/project/-/snippets/903",
				"files": []map[string]any{{
					"path":    "canary_aws",
					"raw_url": "http://" + r.Host + "/group/project/-/snippets/903/raw/main/canary_aws",
				}},
			}})
		case "/api/v4/projects/303/snippets/903/files/main/canary_aws/raw":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(awsSnippetContent))
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "snippets", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--project", "group/project",
		"--json",
	}, nil, 20*time.Second)

	require.NoError(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, `"project":"group/project"`)
	assert.Contains(t, output, `"snippetId":"903"`)

	requests := getRequests()
	var projectFetched, snippetsListed bool
	for _, req := range requests {
		if req.Path == "/api/v4/projects/group%2Fproject" || req.Path == "/api/v4/projects/group/project" {
			projectFetched = true
		}
		if req.Path == "/api/v4/projects/303/snippets" {
			snippetsListed = true
		}
	}
	assert.True(t, projectFetched, "should resolve project by path")
	assert.True(t, snippetsListed, "should list snippets for resolved project")
}

func TestGitLabSnippetsScan_NamespaceFilter(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/groups/mygroup":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "path": "mygroup", "name": "mygroup"})
		case "/api/v4/groups/7/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":                  202,
				"name":                "subproject",
				"path_with_namespace": "mygroup/subproject",
			}})
		case "/api/v4/projects/202/snippets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":      902,
				"title":   "namespace snippet",
				"web_url": "http://" + r.Host + "/mygroup/subproject/-/snippets/902",
				"files": []map[string]any{{
					"path":    "canary_aws",
					"raw_url": "http://" + r.Host + "/mygroup/subproject/-/snippets/902/raw/main/canary_aws",
				}},
			}})
		case "/api/v4/projects/202/snippets/902/files/main/canary_aws/raw":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(awsSnippetContent))
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "snippets", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--namespace", "mygroup",
		"--json",
	}, nil, 20*time.Second)

	require.NoError(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, `"project":"mygroup/subproject"`)
	assert.Contains(t, output, `"snippetId":"902"`)

	requests := getRequests()
	var groupFetched, groupProjectsListed bool
	for _, req := range requests {
		if req.Path == "/api/v4/groups/mygroup" {
			groupFetched = true
		}
		if req.Path == "/api/v4/groups/7/projects" {
			groupProjectsListed = true
			assert.Contains(t, req.RawQuery, "include_subgroups=true")
		}
	}
	assert.True(t, groupFetched, "should resolve namespace to group")
	assert.True(t, groupProjectsListed, "should list namespace projects")
}

func TestGitLabSnippetsScan_ProjectAndNamespaceExclusive(t *testing.T) {
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "snippets", "scan",
		"--gitlab", "https://gitlab.example.com",
		"--token", "glpat-test-token",
		"--project", "group/project",
		"--namespace", "group",
	}, nil, 10*time.Second)

	require.Error(t, exitErr)
	assert.Contains(t, stdout+stderr, "--project and --namespace are mutually exclusive")
}

func TestGitLabSnippetsScan_SearchFlagIsForwarded(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
		}
	})
	defer cleanup()

	_, _, exitErr := testutil.RunCLI(t, []string{
		"gl", "snippets", "scan",
		"--gitlab", server.URL,
		"--token", "glpat-test-token",
		"--member",
		"--search", "needle",
	}, nil, 10*time.Second)

	require.NoError(t, exitErr)

	requests := getRequests()
	projectRequests := 0
	for _, req := range requests {
		if req.Path == "/api/v4/projects" {
			projectRequests++
			assert.True(t, strings.Contains(req.RawQuery, "search=needle"), "search query should be forwarded")
		}
	}
	assert.Greater(t, projectRequests, 0, "should request filtered project listing")
}
