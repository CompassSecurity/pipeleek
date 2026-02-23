package testutil

// Shared test utilities for e2e tests.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// RecordedRequest captures details of an HTTP request received by the mock server
type RecordedRequest struct {
	Method      string
	Path        string
	RawQuery    string
	Headers     http.Header
	Body        []byte
	ReceivedAt  time.Time
	ContentType string
}

type mockServerHandler struct {
	mu       sync.Mutex
	requests []RecordedRequest
	handler  http.HandlerFunc
}

func (m *mockServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Record the request
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	m.mu.Lock()
	m.requests = append(m.requests, RecordedRequest{
		Method:      r.Method,
		Path:        r.URL.Path,
		RawQuery:    r.URL.RawQuery,
		Headers:     r.Header.Clone(),
		Body:        bodyBytes,
		ReceivedAt:  time.Now(),
		ContentType: r.Header.Get("Content-Type"),
	})
	m.mu.Unlock()

	m.handler(w, r)
}

// StartMockServer creates a new HTTP test server with request recording
func StartMockServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, func() []RecordedRequest, func()) {
	t.Helper()
	mh := &mockServerHandler{handler: handler}
	server := httptest.NewServer(mh)
	cleanup := func() { server.Close() }
	get := func() []RecordedRequest {
		mh.mu.Lock()
		defer mh.mu.Unlock()
		return append([]RecordedRequest{}, mh.requests...)
	}
	return server, get, cleanup
}

// StartMockServerWithRecording is an alias for StartMockServer for compatibility
func StartMockServerWithRecording(t *testing.T, handler http.HandlerFunc) (*httptest.Server, func() []RecordedRequest, func()) {
	return StartMockServer(t, handler)
}

// AssertLogContains checks if the output contains all expected strings
func AssertLogContains(t *testing.T, output string, expected []string) {
	t.Helper()
	for _, exp := range expected {
		if !strings.Contains(output, exp) {
			t.Errorf("expected output to contain %q, but it didn't.\nOutput:\n%s", exp, output)
		}
	}
}

// RunCLI executes the Pipeleek CLI binary with args, capturing stdout/stderr, with timeout.
// It is safe to call from parallel tests.
func RunCLI(t *testing.T, args []string, env []string, timeout time.Duration) (stdout, stderr string, exitErr error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Build a per-invocation environment: start from the current process env,
	// disable config file loading for deterministic e2e tests, then apply overrides.
	// We never mutate os.Environ or os.Stdout/os.Stderr so parallel calls are safe.
	envMap := make(map[string]string, len(os.Environ())+1)
	for _, e := range os.Environ() {
		if k, v, ok := strings.Cut(e, "="); ok {
			envMap[k] = v
		}
	}
	envMap["PIPELEEK_NO_CONFIG"] = "1"
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok {
			envMap[k] = v
		}
	}
	envSlice := make([]string, 0, len(envMap))
	for k, v := range envMap {
		envSlice = append(envSlice, k+"="+v)
	}

	var outBuf, errBuf bytes.Buffer
	err := executeCLI(ctx, args, envSlice, &outBuf, &errBuf)

	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("command timed out after %v", timeout)
	}

	return outBuf.String(), errBuf.String(), err
}

// --- Binary execution integration ---

var (
	pipeleekBinaryResolved string
	pipeleekBinaryBuildErr error
	buildOnce              sync.Once
)

func buildBinary(moduleDir, outputPath string) error {
	cmd := exec.Command("go", "build", "-o", outputPath, "./cmd/pipeleek")
	cmd.Dir = moduleDir
	cmd.Env = os.Environ()
	return cmd.Run()
}

// findModuleRoot searches upwards for a directory containing go.mod and cmd/pipeleek/main.go (the CLI entry)
func findModuleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			// Prefer a module that has cmd/pipeleek/main.go (our CLI entry point)
			if _, err := os.Stat(filepath.Join(dir, "cmd", "pipeleek", "main.go")); err == nil {
				return dir, nil
			}
			// If no cmd/pipeleek/main.go here, this is still the module root
			return dir, nil
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return "", fmt.Errorf("module root not found from %s", wd)
}

// resolveBinary returns the path to the pipeleek binary, building it once if necessary.
func resolveBinary() (string, error) {
	if binPath := os.Getenv("PIPELEEK_BINARY"); binPath != "" {
		if !filepath.IsAbs(binPath) {
			if moduleDir, err := findModuleRoot(); err == nil {
				absPath := filepath.Join(moduleDir, binPath)
				if _, err := os.Stat(absPath); err == nil {
					return absPath, nil
				}
			}
		}
		return binPath, nil
	}

	buildOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "pipeleek-e2e-")
		if err != nil {
			pipeleekBinaryBuildErr = err
			return
		}
		tmpBin := filepath.Join(tmpDir, "pipeleek")
		if runtime.GOOS == "windows" {
			tmpBin += ".exe"
		}
		moduleDir, err := findModuleRoot()
		if err != nil {
			pipeleekBinaryBuildErr = err
			return
		}
		if err := buildBinary(moduleDir, tmpBin); err != nil {
			pipeleekBinaryBuildErr = err
			return
		}
		pipeleekBinaryResolved = tmpBin
	})

	if pipeleekBinaryBuildErr != nil {
		return "", fmt.Errorf("failed to build pipeleek test binary: %w", pipeleekBinaryBuildErr)
	}
	return pipeleekBinaryResolved, nil
}

// executeCLI runs the CLI as a separate process, writing output to the provided writers.
// It uses no global state so it is safe to call concurrently.
func executeCLI(ctx context.Context, args []string, env []string, stdout, stderr io.Writer) error {
	binPath, err := resolveBinary()
	if err != nil {
		return err
	}

	// #nosec G204 -- binPath is the test binary path, intentionally variable for testing
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// JSON helpers
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// AssertRequestHeader verifies a request has the expected header value
func AssertRequestHeader(t *testing.T, req RecordedRequest, header, expected string) {
	t.Helper()
	actual := req.Headers.Get(header)
	if actual != expected {
		t.Errorf("Expected header %s=%q, got %q", header, expected, actual)
	}
}

// AssertRequestMethodAndPath verifies a request has the expected method and path
func AssertRequestMethodAndPath(t *testing.T, req RecordedRequest, method, path string) {
	t.Helper()
	if req.Method != method {
		t.Errorf("Expected method %s, got %s for path %s", method, req.Method, req.Path)
	}
	if req.Path != path {
		t.Errorf("Expected path %s, got %s", path, req.Path)
	}
}

// WithError returns a handler that always returns an error status
func WithError(statusCode int, message string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   message,
			"message": message,
		})
	}
}

// MockSuccessResponse returns a handler that always returns a success response
func MockSuccessResponse() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"message": "Operation completed successfully",
		})
	}
}

// DumpRequests prints all recorded requests for debugging
func DumpRequests(t *testing.T, requests []RecordedRequest) {
	t.Helper()
	t.Log("Recorded HTTP requests:")
	for i, req := range requests {
		t.Logf("Request %d:", i+1)
		t.Logf("  Method: %s", req.Method)
		t.Logf("  Path: %s", req.Path)
		if req.RawQuery != "" {
			t.Logf("  Query: %s", req.RawQuery)
		}
		t.Logf("  Headers:")
		for k, v := range req.Headers {
			t.Logf("    %s: %s", k, strings.Join(v, ", "))
		}
		if len(req.Body) > 0 {
			t.Logf("  Body: %s", string(req.Body))
		}
	}
}
