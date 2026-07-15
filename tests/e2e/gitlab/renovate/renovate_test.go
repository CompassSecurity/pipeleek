//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

type capturedRepoFile struct {
	Path       string
	Content    string
	Executable bool
}

func setupMockGitLabRenovateAPI(t *testing.T) string {
	mux := http.NewServeMux()
	// Generic project GET handler to support numeric id or path-based project lookups
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// return a generic project object for any project identifier
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":123,"name":"test-repo","name_with_namespace":"group/test-repo","web_url":"https://gitlab.com/test-repo","default_branch":"main","access_levels":{"project_access_level":40,"group_access_level":0},"permissions":{"project_access":{"access_level":40},"group_access":{"access_level":0}}}`))
			return
		}
		// fallback
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// list projects
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"id":123,"name":"test-repo","web_url":"https://gitlab.com/test-repo"}]`))
			return
		}
		// create project
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":123,"name":"test-repo","web_url":"https://gitlab.com/test-repo"}`))
	})
	mux.HandleFunc("/api/v4/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":456,"username":"renovate-bot","name":"Renovate Bot","web_url":"https://gitlab.com/renovate-bot","bot":true,"private_profile":false}]`))
	})
	mux.HandleFunc("/api/v4/users/456/events", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"action_name":"pushed","target_title":"renovate update","push_data":{"ref":"renovate/deps"}}]`))
	})
	mux.HandleFunc("/api/v4/projects/123", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":123,"name":"test-repo","web_url":"https://gitlab.com/test-repo"}`))
	})
	mux.HandleFunc("/api/v4/projects/123/members", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":456,"access_level":40}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":456,"access_level":40}]`))
	})

	// emulate branch creation: first call returns existing main branch, subsequent calls include the renovate branch
	branchCalls := 0
	mux.HandleFunc("/api/v4/projects/123/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		branchCalls++
		w.WriteHeader(http.StatusOK)
		if branchCalls == 1 {
			w.Write([]byte(`[{"name":"main"}]`))
			return
		}
		w.Write([]byte(`[{"name":"main"},{"name":"renovate/test-branch"}]`))
	})
	mux.HandleFunc("/api/v4/projects/123/pipeline", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":789,"status":"success"}`))
	})

	// handle repository files create/update
	mux.HandleFunc("/api/v4/projects/123/repository/files/", func(w http.ResponseWriter, r *http.Request) {
		// any file create/update should return success
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"file_path":"renovate.json","branch":"main","commit_id":"abc123"}`))
			return
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"file_path":"renovate.json","branch":"main","commit_id":"def456"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"file_path":"renovate.json"}`))
	})

	// raw file retrieval for .gitlab-ci.yml
	mux.HandleFunc("/api/v4/projects/123/repository/files/.gitlab-ci.yml/raw", func(w http.ResponseWriter, r *http.Request) {
		// return a minimal CI/CD YAML
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test-job:\n  script:\n    - echo hello"))
	})

	// CI lint endpoint to provide merged_yaml (used by FetchCICDYml)
	mux.HandleFunc("/api/v4/projects/123/ci/lint", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"valid": true, "merged_yaml": "test-job:\n  script:\n    - echo hello", "warnings": []}`))
	})

	// protected branches lookup for default branch protections
	mux.HandleFunc("/api/v4/projects/123/protected_branches/main", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"main","push_access_levels":[{"access_level":50}],"merge_access_levels":[{"access_level":50}]}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGLRenovateEnum(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "enum",
		"--url", apiURL,
		"--token", "mock-token",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Enum command should succeed")
	assert.Contains(t, stdout, "Fetched all projects")
	assert.NotContains(t, stderr, "error")
}

func TestGLRenovateAutodiscovery(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "autodiscovery",
		"--url", apiURL,
		"--token", "mock-token",
		"--project-name", "test-repo",
		"--username", "test-user",
		"-v",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery command should succeed")
	assert.Contains(t, stdout, "Created project")
	assert.Contains(t, stdout, "Created file", "Should log file creation in verbose mode")
	assert.Contains(t, stdout, "Inviting user")
	assert.Contains(t, stdout, "Maven wrapper", "Should mention Maven wrapper mechanism")
	assert.Contains(t, stdout, "mvnw", "Should mention mvnw script")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRenovateAutodiscoveryWithCICD(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "autodiscovery",
		"--url", apiURL,
		"--token", "mock-token",
		"--project-name", "test-repo-cicd",
		"--username", "test-user",
		"--add-renovate-cicd-for-debugging",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery with CICD flag should succeed")
	assert.Contains(t, stdout, "Created project")
	assert.Contains(t, stdout, "Created .gitlab-ci.yml")
	assert.Contains(t, stdout, "RENOVATE_TOKEN", "Should mention token setup")
	assert.Contains(t, stdout, "api", "Should mention api scope requirement")
	assert.Contains(t, stdout, "maintainer", "Should mention maintainer role requirement")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRenovateAutodiscoveryWithoutUsername(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "autodiscovery",
		"--url", apiURL,
		"--token", "mock-token",
		"--project-name", "test-repo-no-user",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Autodiscovery without username should succeed")
	assert.Contains(t, stdout, "Created project")
	assert.Contains(t, stdout, "No username provided")
	assert.Contains(t, stdout, "invite the victim Renovate Bot user manually")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRenovatePrivesc(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "privesc",
		"--url", apiURL,
		"--token", "mock-token",
		"--repo", "test-repo",
		"--renovate-branches-regex", "renovate/.*",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Privesc command should succeed")
	assert.Contains(t, stdout, "Ensure the Renovate bot")
	assert.Contains(t, stdout, "renovate/test-branch")
	assert.NotContains(t, stderr, "fatal")
}
func TestGLRenovatePrivescWithMonitoringInterval(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "privesc",
		"--url", apiURL,
		"--token", "mock-token",
		"--repo", "test-repo",
		"--renovate-branches-regex", "renovate/.*",
		"--monitoring-interval", "500ms",
	}, nil, 10*time.Second)
	assert.Nil(t, exitErr, "Privesc command with monitoring-interval should succeed")
	assert.Contains(t, stdout, "Ensure the Renovate bot")
	assert.Contains(t, stdout, "renovate/test-branch")
	assert.NotContains(t, stderr, "fatal")
}

func TestGLRenovatePrivescWithInvalidMonitoringInterval(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "privesc",
		"--url", apiURL,
		"--token", "mock-token",
		"--repo", "test-repo",
		"--renovate-branches-regex", "renovate/.*",
		"--monitoring-interval", "invalid-duration",
	}, nil, 10*time.Second)
	assert.NotNil(t, exitErr, "Privesc command with invalid monitoring-interval should fail")
	// Logs are written to stdout by the application logger
	if !strings.Contains(stderr, "Failed to parse monitoring-interval duration") {
		assert.Contains(t, stdout, "Failed to parse monitoring-interval duration")
	}
}

func TestGLRenovateBots(t *testing.T) {
	apiURL := setupMockGitLabRenovateAPI(t)
	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "bots",
		"--url", apiURL,
		"--token", "mock-token",
		"--term", "renovate",
	}, nil, 10*time.Second)

	assert.Nil(t, exitErr, "Bots command should succeed")
	assert.Contains(t, stdout, "Evaluated GitLab user")
	assert.Contains(t, stdout, "likelyRenovateBot")
	assert.Contains(t, stdout, "Renovate bot user enumeration complete")
	assert.NotContains(t, stderr, "fatal")
}

func skipRenovateContainerProbeIfUnavailable(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping docker-backed renovate contract test in short mode")
	}

	if runtime.GOOS == "windows" {
		t.Skip("Skipping docker-backed renovate contract test on Windows: renovate/renovate:latest does not provide a Windows container image")
	}

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("Skipping contract test because docker is not available: %v", err)
	}

	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("Skipping contract test because git is not available: %v", err)
	}

	dockerInfoCtx, dockerInfoCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dockerInfoCancel()
	if err := exec.CommandContext(dockerInfoCtx, "docker", "info").Run(); err != nil {
		t.Skipf("Skipping contract test because docker daemon is unavailable: %v", err)
	}
}

func captureAutodiscoveryRepoFiles(t *testing.T) map[string]capturedRepoFile {
	t.Helper()

	filesByPath := make(map[string]capturedRepoFile)
	var filesMu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":123,"name":"contract-repo","web_url":"https://gitlab.local/contract-repo"}`))
	})

	mux.HandleFunc("/api/v4/projects/123/repository/files/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		encodedPath := strings.TrimPrefix(r.URL.Path, "/api/v4/projects/123/repository/files/")
		filePath, err := url.PathUnescape(encodedPath)
		if err != nil {
			filePath = encodedPath
		}

		var payload struct {
			Content         string `json:"content"`
			ExecuteFilemode bool   `json:"execute_filemode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"message":"failed to decode payload: %v"}`, err)))
			return
		}

		filesMu.Lock()
		filesByPath[filePath] = capturedRepoFile{
			Path:       filePath,
			Content:    payload.Content,
			Executable: payload.ExecuteFilemode,
		}
		filesMu.Unlock()

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"file_path":"` + filePath + `","branch":"main"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"gl", "renovate", "autodiscovery",
		"--url", server.URL,
		"--token", "mock-token",
		"--project-name", "contract-repo",
		"-v",
	}, nil, 2*time.Minute)
	if exitErr != nil {
		t.Fatalf("autodiscovery command failed: %v\nstdout:\n%s\nstderr:\n%s", exitErr, stdout, stderr)
	}
	assert.NotContains(t, stderr, "fatal")
	assert.Contains(t, stdout, "Created project")

	filesMu.Lock()
	_, hasMvnw := filesByPath["mvnw"]
	_, hasPom := filesByPath["pom.xml"]
	_, hasWrapper := filesByPath[".mvn/wrapper/maven-wrapper.properties"]
	_, hasExploit := filesByPath["exploit.sh"]
	filesSnapshot := make(map[string]capturedRepoFile, len(filesByPath))
	for k, v := range filesByPath {
		filesSnapshot[k] = v
	}
	filesMu.Unlock()

	assert.True(t, hasMvnw, "autodiscovery should create mvnw")
	assert.True(t, hasPom, "autodiscovery should create pom.xml")
	assert.True(t, hasWrapper, "autodiscovery should create maven wrapper properties")
	assert.True(t, hasExploit, "autodiscovery should create exploit.sh")

	return filesSnapshot
}

func materializeAutodiscoveryRepoFixture(t *testing.T, filesSnapshot map[string]capturedRepoFile) string {
	t.Helper()

	workspaceDir, err := os.MkdirTemp("/workspaces/pipeleek", ".tmp-renovate-fixture-*")
	if err != nil {
		workspaceDir = t.TempDir()
	} else {
		t.Cleanup(func() {
			_ = os.RemoveAll(workspaceDir)
		})
	}
	repoDir := filepath.Join(workspaceDir, "repo")
	requireNoError := func(err error, msg string) {
		if err != nil {
			t.Fatalf("%s: %v", msg, err)
		}
	}
	requireNoError(os.MkdirAll(repoDir, 0o755), "failed to create repo dir")

	for _, file := range filesSnapshot {
		target := filepath.Join(repoDir, filepath.FromSlash(file.Path))
		requireNoError(os.MkdirAll(filepath.Dir(target), 0o755), "failed to create file parent dir")
		mode := os.FileMode(0o644)
		if file.Executable {
			mode = 0o755
		}
		requireNoError(os.WriteFile(target, []byte(file.Content), mode), "failed to write repo file")
	}

	gitCtx, gitCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gitCancel()
	for _, cmdArgs := range [][]string{
		{"init"},
		{"config", "user.email", "contract-test@example.com"},
		{"config", "user.name", "contract-test"},
		{"add", "."},
		{"commit", "-m", "contract test repo"},
	} {
		cmd := exec.CommandContext(gitCtx, "git", cmdArgs...)
		cmd.Dir = repoDir
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git command failed (%v): %v\n%s", cmdArgs, err, string(output))
		}
	}

	return repoDir
}

func startRenovateProbeContainer(t *testing.T, repoDir string) (context.Context, context.CancelFunc, string) {
	t.Helper()

	renovateCtx, renovateCancel := context.WithTimeout(context.Background(), 4*time.Minute)
	containerName := fmt.Sprintf("pipeleek-renovate-e2e-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", containerName).Run()
	})

	createCmd := exec.CommandContext(renovateCtx, "docker", "create", "--name", containerName, "--user", "0:0", "--add-host", "host.docker.internal:host-gateway", "--entrypoint", "sleep", "renovate/renovate:latest", "300")
	if createOutput, createErr := createCmd.CombinedOutput(); createErr != nil {
		t.Fatalf("failed to create renovate container: %v\n%s", createErr, string(createOutput))
	}

	cpRepoCmd := exec.CommandContext(renovateCtx, "docker", "cp", repoDir+"/.", containerName+":/tmp/repo")
	if cpRepoOutput, cpRepoErr := cpRepoCmd.CombinedOutput(); cpRepoErr != nil {
		t.Fatalf("failed to copy generated repo into renovate container: %v\n%s", cpRepoErr, string(cpRepoOutput))
	}

	startCmd := exec.CommandContext(renovateCtx, "docker", "start", containerName)
	if startOutput, startErr := startCmd.CombinedOutput(); startErr != nil {
		t.Fatalf("failed to start renovate container: %v\n%s", startErr, string(startOutput))
	}

	initGitArgs := []string{
		"exec",
		"-w", "/tmp/repo",
		containerName,
		"sh",
		"-lc",
		"git init && git config user.email contract-test@example.com && git config user.name contract-test && git add . && (git commit -m 'contract test repo' || true)",
	}
	initGitCmd := exec.CommandContext(renovateCtx, "docker", initGitArgs...)
	if initGitOutput, initGitErr := initGitCmd.CombinedOutput(); initGitErr != nil {
		t.Fatalf("failed to initialize git repo inside container: %v\n%s", initGitErr, string(initGitOutput))
	}

	return renovateCtx, renovateCancel, containerName
}

func reserveLocalPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve local port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func startGitDaemonForRepo(t *testing.T, repoDir string) string {
	t.Helper()

	serveRoot := t.TempDir()
	bareRepoPath := filepath.Join(serveRoot, "contract-repo.git")

	cloneCtx, cloneCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cloneCancel()
	cloneCmd := exec.CommandContext(cloneCtx, "git", "clone", "--bare", repoDir, bareRepoPath)
	if cloneOutput, cloneErr := cloneCmd.CombinedOutput(); cloneErr != nil {
		t.Fatalf("failed to create bare repo for git daemon: %v\n%s", cloneErr, string(cloneOutput))
	}

	port := reserveLocalPort(t)
	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	daemonCmd := exec.CommandContext(
		daemonCtx,
		"git",
		"daemon",
		"--reuseaddr",
		"--verbose",
		"--export-all",
		"--enable=receive-pack",
		"--base-path="+serveRoot,
		"--listen=0.0.0.0",
		"--port="+strconv.Itoa(port),
		serveRoot,
	)
	if daemonErr := daemonCmd.Start(); daemonErr != nil {
		t.Fatalf("failed to start git daemon: %v", daemonErr)
	}
	t.Cleanup(func() {
		daemonCancel()
		waitDone := make(chan struct{})
		go func() {
			_ = daemonCmd.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(5 * time.Second):
			_ = daemonCmd.Process.Kill()
		}
	})

	cloneURL := fmt.Sprintf("git://127.0.0.1:%d/contract-repo.git", port)
	return cloneURL
}

func runRenovateProbeWithHostNpx(t *testing.T, repoDir, endpoint string) string {
	t.Helper()

	probeCtx, probeCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer probeCancel()

	cmd := exec.CommandContext(
		probeCtx,
		"npx",
		"-y",
		"-p", "node@24.11.0",
		"-p", "renovate@latest",
		"renovate",
		"--platform=gitlab",
		"--endpoint="+endpoint,
		"--token=mock-token",
		"--git-url=ssh",
		"--require-config=ignored",
		"--onboarding=false",
		"--enabled-managers=maven,maven-wrapper",
		"group/contract-repo",
	)
	cmd.Dir = repoDir
	cmd.Env = append(os.Environ(),
		"LOG_LEVEL=debug",
		"RENOVATE_PLATFORM=gitlab",
		"RENOVATE_ENDPOINT="+endpoint,
		"RENOVATE_TOKEN=mock-token",
		"RENOVATE_GIT_URL=ssh",
		"RENOVATE_REQUIRE_CONFIG=ignored",
		"RENOVATE_ONBOARDING=false",
		"RENOVATE_ENABLED_MANAGERS=maven,maven-wrapper",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output)
	}
	return string(output)
}

func startMockGitLabAutodiscoveryAPI(t *testing.T, cloneURL string) (string, func() string) {
	t.Helper()

	projectPayload := fmt.Sprintf(`{"id":123,"name":"contract-repo","path_with_namespace":"group/contract-repo","web_url":"https://gitlab.local/group/contract-repo","default_branch":"main","archived":false,"empty_repo":false,"mirror":false,"repository_access_level":"enabled","merge_requests_access_level":"enabled","merge_method":"merge","merge_trains_enabled":false,"squash_option":"default_on","http_url_to_repo":"%s","ssh_url_to_repo":"%s"}`,
		cloneURL,
		cloneURL,
	)

	var requestsMu sync.Mutex
	requests := make([]string, 0, 32)
	record := func(r *http.Request) {
		requestsMu.Lock()
		defer requestsMu.Unlock()
		requests = append(requests, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/version", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version":"17.0.0"}`))
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1,"name":"Renovate Bot","email":"renovate@example.com","username":"renovate-bot"}`))
	})
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[" + projectPayload + "]"))
	})
	mux.HandleFunc("/api/v4/projects/group%2Fcontract-repo", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(projectPayload))
	})
	mux.HandleFunc("/api/v4/projects/123", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(projectPayload))
	})
	mux.HandleFunc("/api/v4/projects/group/contract-repo", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(projectPayload))
	})
	mux.HandleFunc("/api/v4/projects/group/contract-repo/merge_requests", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"iid":2,"title":"Renovate Update","state":"opened","web_url":"https://gitlab.local/group/contract-repo/-/merge_requests/2"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	})
	mux.HandleFunc("/api/v4/projects/group/contract-repo/repository/commits/main/statuses", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	})
	mux.HandleFunc("/api/v4/projects/group/contract-repo/labels", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	})
	mux.HandleFunc("/api/v4/projects/123/merge_requests", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"iid":2,"title":"Renovate Update","state":"opened","web_url":"https://gitlab.local/group/contract-repo/-/merge_requests/2"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	})
	mux.HandleFunc("/api/v4/projects/123/repository/commits/main/statuses", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	})
	mux.HandleFunc("/api/v4/projects/123/labels", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	})

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler, pattern := mux.Handler(r); pattern != "" {
			handler.ServeHTTP(w, r)
			return
		}
		record(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Default: return [] for GET (list endpoints) and {} for others
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("[]"))
		} else {
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to bind mock gitlab listener: %v", err)
	}
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	port := server.Listener.Addr().(*net.TCPAddr).Port
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/api/v4/", port)
	dumpRequests := func() string {
		requestsMu.Lock()
		defer requestsMu.Unlock()
		if len(requests) == 0 {
			return "(no API calls recorded)"
		}
		return strings.Join(requests, "\n")
	}

	return endpoint, dumpRequests
}

func runRenovateProbe(t *testing.T, renovateCtx context.Context, containerName, endpoint string) string {
	t.Helper()

	execArgs := []string{
		"exec",
		"-e", "LOG_LEVEL=debug",
		"-e", "RENOVATE_PLATFORM=gitlab",
		"-e", "RENOVATE_ENDPOINT=" + endpoint,
		"-e", "RENOVATE_TOKEN=mock-token",
		"-e", "RENOVATE_GIT_URL=ssh",
		"-e", "RENOVATE_REQUIRE_CONFIG=ignored",
		"-e", "RENOVATE_ONBOARDING=false",
		"-e", "RENOVATE_ENABLED_MANAGERS=maven,maven-wrapper",
		"-e", "RENOVATE_LOG_LEVEL=debug",
		"-e", "RENOVATE_LOG_FILE=/tmp/pipeleek-renovate-internal.log",
		"-e", "RENOVATE_X_HARD_EXIT=1",
		"-w", "/tmp/repo",
		containerName,
		"/usr/local/renovate/node",
		"/usr/local/renovate/dist/renovate.js",
		"--platform=gitlab",
		"--endpoint=" + endpoint,
		"--token=mock-token",
		"--git-url=ssh",
		"--repositories=group/contract-repo",
		"--require-config=ignored",
		"--onboarding=false",
		"--enabled-managers=maven,maven-wrapper",
	}
	renovateCmd := exec.CommandContext(renovateCtx, "docker", execArgs...)
	renovateOutput, renovateErr := renovateCmd.CombinedOutput()
	renovateOutputStr := string(renovateOutput)
	if renovateErr != nil {
		t.Fatalf("renovate command failed: %v\n%s", renovateErr, renovateOutputStr)
	}

	return renovateOutputStr
}

func readExploitProofFromContainer(t *testing.T, renovateCtx context.Context, containerName string) (string, bool) {
	t.Helper()

	proofCmd := exec.CommandContext(
		renovateCtx,
		"docker",
		"exec",
		"-w", "/tmp/repo",
		containerName,
		"sh",
		"-lc",
		"cat /tmp/pipeleek-exploit-executed.txt",
	)
	proofOutput, proofErr := proofCmd.CombinedOutput()
	if proofErr == nil {
		return string(proofOutput), true
	}

	var exitErr *exec.ExitError
	if errors.As(proofErr, &exitErr) {
		return "", false
	}

	t.Fatalf("failed to check exploit proof file in renovate container: %v\n%s", proofErr, string(proofOutput))
	return "", false
}

func verifyContainerCanReachEndpoint(t *testing.T, renovateCtx context.Context, containerName, endpoint string) string {
	t.Helper()

	probeCmd := exec.CommandContext(
		renovateCtx,
		"docker",
		"exec",
		containerName,
		"sh",
		"-lc",
		fmt.Sprintf("curl -sS -i --max-time 10 %q", endpoint+"version"),
	)
	probeOutput, probeErr := probeCmd.CombinedOutput()
	if probeErr != nil {
		t.Fatalf("failed to reach mock gitlab endpoint from renovate container: %v\n%s", probeErr, string(probeOutput))
	}
	return string(probeOutput)
}

func readRenovateProbeLogFromContainer(t *testing.T, renovateCtx context.Context, containerName string) string {
	t.Helper()

	logCmd := exec.CommandContext(
		renovateCtx,
		"docker",
		"exec",
		containerName,
		"sh",
		"-lc",
		"if [ -f /tmp/pipeleek-renovate-output.log ]; then cat /tmp/pipeleek-renovate-output.log; else echo '(probe log file missing)'; fi; echo; echo '--- renovate internal log ---'; if [ -f /tmp/pipeleek-renovate-internal.log ]; then cat /tmp/pipeleek-renovate-internal.log; else echo '(internal log file missing)'; fi",
	)
	logOutput, logErr := logCmd.CombinedOutput()
	if logErr != nil {
		return fmt.Sprintf("(failed reading probe log: %v)\n%s", logErr, string(logOutput))
	}
	if len(logOutput) == 0 {
		return "(probe log empty)"
	}
	return string(logOutput)
}

func tailForDiagnostics(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[len(value)-max:]
}

func TestGLRenovateAutodiscovery_RenovateLatestPicksUpMavenWrapperExploit(t *testing.T) {
	skipRenovateContainerProbeIfUnavailable(t)
	filesSnapshot := captureAutodiscoveryRepoFiles(t)
	repoDir := materializeAutodiscoveryRepoFixture(t, filesSnapshot)
	cloneURL := startGitDaemonForRepo(t, repoDir)
	endpoint, dumpRequests := startMockGitLabAutodiscoveryAPI(t, cloneURL)

	// Remove any stale proof file from a previous run to avoid false positives.
	_ = os.Remove("/tmp/pipeleek-exploit-executed.txt")

	renovateOutput := runRenovateProbeWithHostNpx(t, repoDir, endpoint)

	proofBytes, proofErr := os.ReadFile("/tmp/pipeleek-exploit-executed.txt")
	proofContent := string(proofBytes)
	proofFound := proofErr == nil
	if !proofFound {
		t.Fatalf(
			"renovate latest completed but did not produce /tmp/pipeleek-exploit-executed.txt; this indicates arbitrary mvnw invocation may no longer happen in the current execution path\nrenovate output tail:\n%s\nmock gitlab requests:\n%s",
			tailForDiagnostics(renovateOutput, 12000),
			dumpRequests(),
		)
	}

	assert.Contains(t, proofContent, "Exploit executed at")
	assert.Contains(t, proofContent, "Working directory:")
	assert.Contains(t, proofContent, "User:")
}
