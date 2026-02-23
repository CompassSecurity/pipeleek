//go:build e2e

package container

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestContainerScanBasic(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/search/repositories") {
			searchResultJSON := `{
"total_count": 1,
"incomplete_results": false,
"items": [
{
"id": 1,
"name": "dangerous-app",
"full_name": "test-user/dangerous-app",
"html_url": "http://localhost/test-user/dangerous-app",
"owner": {
"login": "test-user"
}
}
]
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(searchResultJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/dangerous-app/git/trees/main") {
			treeJSON := `{
"sha": "main",
"tree": [
{"path":"Dockerfile","mode":"100644","type":"blob","sha":"abc123"}
],
"truncated": false
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(treeJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/dangerous-app") &&
			!strings.Contains(r.URL.Path, "/contents") &&
			!strings.Contains(r.URL.Path, "/git/trees") &&
			!strings.Contains(r.URL.Path, "/actions/runs") {
			repoJSON := `{
"id": 1,
"name": "dangerous-app",
"full_name": "test-user/dangerous-app",
"html_url": "http://localhost/test-user/dangerous-app",
"default_branch": "main",
"owner": {
"login": "test-user",
"type": "User"
}
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(repoJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/dangerous-app/contents/Dockerfile") {
			fileJSON := `{
"name": "Dockerfile",
"path": "Dockerfile",
"sha": "abc123",
"size": 150,
"type": "file",
"encoding": "base64",
"content": "RlJPTSB1YnVudHU6MjIuMDQKUlVOIGFwdC1nZXQgdXBkYXRlICYmIGFwdC1nZXQgaW5zdGFsbCAteSBjdXJsCkNPUFkgLiAvYXBwCldPUktESVIgL2FwcApSVU4gLi9pbnN0YWxsLnNoCkVOVFJZUE9JTlQgWyIuL3N0YXJ0LnNoIl0="
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fileJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/dangerous-app/actions/runs") {
			runsJSON := `{
"total_count": 1,
"workflow_runs": [
{"id": 42, "updated_at": "2026-02-22T12:00:00Z"}
]
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(runsJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/orgs/test-user/packages") && !strings.Contains(r.URL.Path, "/versions") {
			packagesJSON := `[
{"name": "dangerous-app"}
]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(packagesJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/orgs/test-user/packages/container/dangerous-app/versions") {
			versionsJSON := `[
{"name":"sha256:abc","created_at":"2026-02-22T11:59:00Z","metadata":{"container":{"tags":["latest"]}}}
]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(versionsJSON))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "container", "artipacked",
		"--github", server.URL,
		"--token", "test-token",
		"--public",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Identified")
	assert.Contains(t, output, "test-user/dangerous-app")
	assert.Contains(t, output, "latest_ci_run_at")
	assert.Contains(t, output, "registry_tag")
	assert.Contains(t, output, "registry_last_update")
	assert.NotContains(t, output, "registry_created_at")
}

func TestContainerScanOwned(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/search/repositories") {
			searchResultJSON := `{
"total_count": 1,
"incomplete_results": false,
"items": [
{
"id": 1,
"name": "my-repo",
"full_name": "test-user/my-repo",
"html_url": "http://localhost/test-user/my-repo",
"owner": {
"login": "test-user"
}
}
]
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(searchResultJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/my-repo/git/trees/main") {
			treeJSON := `{
"sha": "main",
"tree": [
{"path":"Dockerfile","mode":"100644","type":"blob","sha":"abc123"}
],
"truncated": false
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(treeJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/my-repo") &&
			!strings.Contains(r.URL.Path, "/contents") &&
			!strings.Contains(r.URL.Path, "/git/trees") {
			repoJSON := `{
"id": 1,
"name": "my-repo",
"full_name": "test-user/my-repo",
"html_url": "http://localhost/test-user/my-repo",
"default_branch": "main",
"owner": {
"login": "test-user",
"type": "User"
}
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(repoJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/my-repo/contents/Dockerfile") {
			fileJSON := `{
"name": "Dockerfile",
"path": "Dockerfile",
"encoding": "base64",
"content": "RlJPTSB1YnVudHUKQ09QWSAuIC8KUlVOIGVjaG8gZG9uZQ=="
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fileJSON))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "container", "artipacked",
		"--github", server.URL,
		"--token", "test-token",
		"--owned",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Identified")
}

func TestContainerScanOrganization(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/orgs/my-org/repos") {
			reposJSON := `[
{
"id": 1,
"name": "test-project",
"full_name": "my-org/test-project",
"html_url": "http://localhost/my-org/test-project",
"owner": {
"login": "my-org",
"type": "Organization"
}
}
]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(reposJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/my-org/test-project") &&
			!strings.Contains(r.URL.Path, "/contents") &&
			!strings.Contains(r.URL.Path, "/git/trees") {
			repoJSON := `{
"id": 1,
"name": "test-project",
"full_name": "my-org/test-project",
"html_url": "http://localhost/my-org/test-project",
"default_branch": "main",
"owner": {
"login": "my-org",
"type": "Organization"
}
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(repoJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/my-org/test-project/git/trees/main") {
			treeJSON := `{
"sha": "main",
"tree": [
{"path":"Dockerfile","mode":"100644","type":"blob","sha":"abc123"}
],
"truncated": false
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(treeJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/my-org/test-project/contents/Dockerfile") {
			fileJSON := `{
"name": "Dockerfile",
"path": "Dockerfile",
"encoding": "base64",
"content": "RlJPTSBhbHBpbmUKQ09QWSAuIC90ZXN0CkNNRCBbXCIvYmluL3NoXCJd"
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fileJSON))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "container", "artipacked",
		"--github", server.URL,
		"--token", "test-token",
		"--organization", "my-org",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Identified")
	assert.Contains(t, output, "my-org/test-project")
}

func TestContainerScanSingleRepo(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/test-user/test-repo") &&
			!strings.Contains(r.URL.Path, "/contents") &&
			!strings.Contains(r.URL.Path, "/git/trees") {
			repoJSON := `{
"id": 1,
"name": "test-repo",
"full_name": "test-user/test-repo",
"html_url": "http://localhost/test-user/test-repo",
"default_branch": "main",
"owner": {
"login": "test-user",
"type": "User"
}
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(repoJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/test-repo/git/trees/main") {
			treeJSON := `{
"sha": "main",
"tree": [
{"path":"Dockerfile","mode":"100644","type":"blob","sha":"abc123"}
],
"truncated": false
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(treeJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/test-repo/contents/Dockerfile") {
			fileJSON := `{
"name": "Dockerfile",
"path": "Dockerfile",
"encoding": "base64",
"content": "RlJPTSB1YnVudHUKQUREIC4gL2FwcApSVU4gbWFrZSBidWlsZA=="
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fileJSON))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "container", "artipacked",
		"--github", server.URL,
		"--token", "test-token",
		"--repo", "test-user/test-repo",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Identified")
	assert.Contains(t, output, "test-user/test-repo")
}

func TestContainerScanNoDockerfile(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/search/repositories") {
			searchResultJSON := `{
"total_count": 1,
"incomplete_results": false,
"items": [
{
"id": 1,
"name": "no-docker",
"full_name": "test-user/no-docker",
"html_url": "http://localhost/test-user/no-docker",
"owner": {
"login": "test-user"
}
}
]
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(searchResultJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/no-docker") &&
			!strings.Contains(r.URL.Path, "/contents") &&
			!strings.Contains(r.URL.Path, "/git/trees") {
			repoJSON := `{
"id": 1,
"name": "no-docker",
"full_name": "test-user/no-docker",
"html_url": "http://localhost/test-user/no-docker",
"default_branch": "main",
"owner": {
"login": "test-user",
"type": "User"
}
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(repoJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/no-docker/git/trees/main") {
			treeJSON := `{
"sha": "main",
"tree": [
{"path":"README.md","mode":"100644","type":"blob","sha":"def456"}
],
"truncated": false
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(treeJSON))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "container", "artipacked",
		"--github", server.URL,
		"--token", "test-token",
		"--public",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Container scan complete")
	assert.NotContains(t, output, "Identified")
}

func TestContainerScanMissingToken(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gh", "container", "artipacked",
		"--github", server.URL,
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.NotNil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing")
}
