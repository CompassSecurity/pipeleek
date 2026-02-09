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

		if strings.Contains(r.URL.Path, "/search/code") {
			codeResultJSON := `{
"total_count": 1,
"incomplete_results": false,
"items": [
{
"name": "Dockerfile",
"path": "Dockerfile",
"sha": "abc123",
"url": "http://localhost/test-user/dangerous-app/contents/Dockerfile",
"repository": {
"id": 1,
"name": "dangerous-app",
"full_name": "test-user/dangerous-app"
}
}
]
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(codeResultJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/dangerous-app") &&
			!strings.Contains(r.URL.Path, "/contents") {
			repoJSON := `{
"id": 1,
"name": "dangerous-app",
"full_name": "test-user/dangerous-app",
"html_url": "http://localhost/test-user/dangerous-app",
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
}

func TestContainerScanOwned(t *testing.T) {
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

		if strings.Contains(r.URL.Path, "/search/code") {
			codeResultJSON := `{
"total_count": 1,
"incomplete_results": false,
"items": [
{
"name": "Dockerfile",
"path": "Dockerfile"
}
]
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(codeResultJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repos/test-user/my-repo") &&
			!strings.Contains(r.URL.Path, "/contents") {
			repoJSON := `{
"id": 1,
"name": "my-repo",
"full_name": "test-user/my-repo",
"html_url": "http://localhost/test-user/my-repo",
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

		if strings.Contains(r.URL.Path, "/search/code") {
			codeResultJSON := `{
"total_count": 1,
"incomplete_results": false,
"items": [
{
"name": "Dockerfile",
"path": "Dockerfile"
}
]
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(codeResultJSON))
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
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/test-user/test-repo") &&
			!strings.Contains(r.URL.Path, "/contents") {
			repoJSON := `{
"id": 1,
"name": "test-repo",
"full_name": "test-user/test-repo",
"html_url": "http://localhost/test-user/test-repo",
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

		if strings.Contains(r.URL.Path, "/search/code") {
			codeResultJSON := `{
"total_count": 1,
"incomplete_results": false,
"items": [
{
"name": "Dockerfile",
"path": "Dockerfile"
}
]
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(codeResultJSON))
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

		if strings.Contains(r.URL.Path, "/search/code") {
			codeResultJSON := `{
"total_count": 0,
"incomplete_results": false,
"items": []
}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(codeResultJSON))
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
