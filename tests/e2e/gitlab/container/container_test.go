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
		if strings.Contains(r.URL.Path, "/api/v4/projects") &&
			!strings.Contains(r.URL.Path, "/repository/files") &&
			!strings.Contains(r.URL.Path, "/repository/tree") {
			projectsJSON := `[
{
"id": 1,
"path_with_namespace": "test-user/dangerous-app",
"web_url": "http://localhost/test-user/dangerous-app"
},
{
"id": 2,
"path_with_namespace": "test-user/safe-app",
"web_url": "http://localhost/test-user/safe-app"
}
]`
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total", "2")
			w.Header().Set("X-Total-Pages", "1")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(projectsJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/tree") {
			if strings.Contains(r.URL.Path, "/1/") {
				treeJSON := `[
{"id":"abc123","name":"Dockerfile","type":"blob","path":"Dockerfile","mode":"100644"}
]`
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(treeJSON))
				return
			}
			if strings.Contains(r.URL.Path, "/2/") {
				treeJSON := `[
{"id":"def456","name":"Dockerfile","type":"blob","path":"Dockerfile","mode":"100644"}
]`
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(treeJSON))
				return
			}
		}

		if strings.Contains(r.URL.Path, "/repository/files") && strings.Contains(r.URL.Path, "Dockerfile") {
			if strings.Contains(r.URL.Path, "/1/") {
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"file_name":"Dockerfile","file_path":"Dockerfile","size":150,"content":"RlJPTSB1YnVudHU6MjIuMDQKUlVOIGFwdC1nZXQgdXBkYXRlICYmIGFwdC1nZXQgaW5zdGFsbCAteSBjdXJsCkNPUFkgLiAvYXBwCldPUktESVIgL2FwcApSVU4gLi9pbnN0YWxsLnNoCkVOVFJZUE9JTlQgWyIuL3N0YXJ0LnNoIl0="}`))
				return
			}
			if strings.Contains(r.URL.Path, "/2/") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"file_name":"Dockerfile","file_path":"Dockerfile","size":100,"content":"RlJPTSB1YnVudHU6MjIuMDQKUlVOIGFwdC1nZXQgdXBkYXRlICYmIGFwdC1nZXQgaW5zdGFsbCAteSBjdXJsCkNPUFkgcmVxdWlyZW1lbnRzLnR4dCAvYXBwLwpXT1JLRElSIC9hcHAKUlVOIHBpcCBpbnN0YWxsIC1yIHJlcXVpcmVtZW50cy50eHQKQ01EIFsicHl0aG9uIiwgImFwcC5weSJd"}`))
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "container", "artipacked",
		"--gitlab", server.URL,
		"--token", "test-token",
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
		if strings.Contains(r.URL.Path, "/api/v4/projects") &&
			!strings.Contains(r.URL.Path, "/repository/files") &&
			!strings.Contains(r.URL.Path, "/repository/tree") {
			if !strings.Contains(r.URL.RawQuery, "owned=true") {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"message": "owned param required"}`))
				return
			}

			projectsJSON := `[
{
"id": 1,
"path_with_namespace": "test-user/my-project",
"web_url": "http://localhost/test-user/my-project"
}
]`
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total", "1")
			w.Header().Set("X-Total-Pages", "1")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(projectsJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/tree") {
			treeJSON := `[
{"id":"abc123","name":"Dockerfile","type":"blob","path":"Dockerfile","mode":"100644"}
]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(treeJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/files") && strings.Contains(r.URL.Path, "Dockerfile") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"file_name":"Dockerfile","file_path":"Dockerfile","size":100,"content":"RlJPTSB1YnVudHUKQ09QWSAuIC8KUlVOIGVjaG8gZG9uZQ=="}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "container", "artipacked",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--owned",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Identified")
}

func TestContainerScanNamespace(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v4/groups/my-group") &&
			!strings.Contains(r.URL.Path, "/projects") {
			groupJSON := `{"id": 10, "name": "my-group", "path": "my-group"}`
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(groupJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/api/v4/groups") &&
			strings.Contains(r.URL.Path, "/projects") {
			projectsJSON := `[
{
"id": 1,
"path_with_namespace": "my-group/test-project",
"web_url": "http://localhost/my-group/test-project"
}
]`
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total", "1")
			w.Header().Set("X-Total-Pages", "1")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(projectsJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/tree") {
			treeJSON := `[
{"id":"abc123","name":"Dockerfile","type":"blob","path":"Dockerfile","mode":"100644"}
]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(treeJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/files") && strings.Contains(r.URL.Path, "Dockerfile") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"file_name":"Dockerfile","file_path":"Dockerfile","content":"RlJPTSBhbHBpbmUKQ09QWSAuIC90ZXN0CkNNRCBbXCIvYmluL3NoXCJd"}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "container", "artipacked",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--namespace", "my-group",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Scanning specific namespace")
	assert.Contains(t, output, "Identified")
}

func TestContainerScanSingleRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GitLab accepts URL-encoded path as the project ID.
		if strings.Contains(r.URL.Path, "/api/v4/projects/") &&
			!strings.Contains(r.URL.Path, "/repository/files") &&
			!strings.Contains(r.URL.Path, "/repository/tree") {
			projectJSON := `{
"id": 1,
"path_with_namespace": "test-user/test-repo",
"web_url": "http://localhost/test-user/test-repo"
}`
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(projectJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/tree") {
			treeJSON := `[
{"id":"abc123","name":"Dockerfile","type":"blob","path":"Dockerfile","mode":"100644"}
]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(treeJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/files") && strings.Contains(r.URL.Path, "Dockerfile") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"file_name":"Dockerfile","file_path":"Dockerfile","content":"RlJPTSB1YnVudHUKQUREIC4gL2FwcApSVU4gbWFrZSBidWlsZA=="}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "container", "artipacked",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--repo", "test-user/test-repo",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Scanning specific repository")
	assert.Contains(t, output, "Identified")
}

func TestContainerScanNoDockerfile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v4/projects") &&
			!strings.Contains(r.URL.Path, "/repository/files") {
			projectsJSON := `[
{
"id": 1,
"path_with_namespace": "test-user/no-docker",
"web_url": "http://localhost/test-user/no-docker"
}
]`
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total", "1")
			w.Header().Set("X-Total-Pages", "1")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(projectsJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/files") && strings.Contains(r.URL.Path, "Dockerfile") {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message": "404 File Not Found"}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "container", "artipacked",
		"--gitlab", server.URL,
		"--token", "test-token",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Container scan complete")
	assert.NotContains(t, output, "Identified")
}

func TestContainerScanInvalidURL(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "container", "artipacked",
		"--gitlab", "https://gitlab.example.com",
		"--token", "test-token",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.NotNil(t, exitErr)
}

func TestContainerScanMissingToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "container", "artipacked",
		"--gitlab", "https://gitlab.example.com",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.NotNil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "required configuration missing")
}

func TestContainerScanWithSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v4/projects") &&
			!strings.Contains(r.URL.Path, "/repository/files") &&
			!strings.Contains(r.URL.Path, "/repository/tree") {
			if !strings.Contains(r.URL.RawQuery, "search=app") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			projectsJSON := `[
{
"id": 1,
"path_with_namespace": "test-user/my-app",
"web_url": "http://localhost/test-user/my-app"
}
]`
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Per-Page", "100")
			w.Header().Set("X-Total", "1")
			w.Header().Set("X-Total-Pages", "1")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(projectsJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/tree") {
			treeJSON := `[
{"id":"abc123","name":"Dockerfile","type":"blob","path":"Dockerfile","mode":"100644"}
]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(treeJSON))
			return
		}

		if strings.Contains(r.URL.Path, "/repository/files") && strings.Contains(r.URL.Path, "Dockerfile") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"file_name":"Dockerfile","file_path":"Dockerfile","content":"RlJPTSBub2RlCkNPUFkgLiAvc3JjClJVTiBucG0gaW5zdGFsbA=="}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "404 Not Found"}`))
	}))
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "container", "artipacked",
		"--gitlab", server.URL,
		"--token", "test-token",
		"--search", "app",
	}, nil, 10*time.Second)

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)

	assert.Nil(t, exitErr)
	output := stdout + stderr
	assert.Contains(t, output, "Identified")
}
