package scan

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nsqio/go-diskqueue"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// withCapturedLogs temporarily routes zerolog output to a buffer for assertions.
func withCapturedLogs(t *testing.T, level zerolog.Level, fn func(buf *bytes.Buffer)) {
	t.Helper()
	old := log.Logger
	buf := &bytes.Buffer{}
	logger := zerolog.New(buf).Level(level).With().Timestamp().Logger()
	log.Logger = logger
	defer func() { log.Logger = old }()
	fn(buf)
}

func TestAnalyzeJobArtifact_SkipsLargeArtifactPreDownload(t *testing.T) {
	// Arrange: artifact is larger than the configured max — should skip before any download
	item := QueueItem{Meta: QueueMeta{
		ProjectId:    1,
		JobId:        3000,
		JobWebUrl:    "http://gitlab.local/-/jobs/3000",
		JobName:      "large-artifact-job",
		ArtifactSize: 100 * 1024 * 1024, // 100MB
	}}
	opts := &ScanOptions{MaxArtifactSize: 50 * 1024 * 1024, MaxScanGoRoutines: 1}

	withCapturedLogs(t, zerolog.DebugLevel, func(buf *bytes.Buffer) {
		// Act: pass nil gitlab client since we expect early return (no network calls)
		analyzeJobArtifact((*gitlab.Client)(nil), item, opts)

		// Assert: log contains skip message and job name
		logs := buf.String()
		if !strings.Contains(logs, "Skipped large artifact") {
			t.Fatalf("expected skip log, got: %s", logs)
		}
		if !strings.Contains(logs, "large-artifact-job") {
			t.Fatalf("expected job name in logs, got: %s", logs)
		}
	})
}

func TestAnalyzeJobArtifact_ReturnsEarlyWhenSizeExceedsPostDownload(t *testing.T) {
	// Note: This test would require mocking the gitlab client to avoid nil pointer dereference.
	// Skipping for now as it requires refactoring getJobArtifacts to be injectable.
	t.Skip("Requires mock client or refactor for testability")
}

func TestGetDotenvArtifact_EmptyCookie(t *testing.T) {
	// Empty cookie should bypass download attempt
	opts := &ScanOptions{GitlabCookie: "", GitlabUrl: "http://gitlab.local"}
	result := getDotenvArtifact(nil, 1, 123, "group/project", opts)
	if len(result) != 0 {
		t.Fatalf("expected nil result with empty cookie, got %d bytes", len(result))
	}
}

func TestGetDotenvArtifact_WithCookie(t *testing.T) {
	// Non-empty cookie should trigger download (which will fail in test but exercises logic)
	opts := &ScanOptions{GitlabCookie: "valid-cookie", GitlabUrl: "http://localhost:65535"}
	result := getDotenvArtifact(nil, 1, 123, "group/project", opts)
	// Expected to return empty on connection failure
	if len(result) != 0 {
		t.Logf("unexpected bytes returned: %d", len(result))
	}
}

func TestEnqueueItem_Marshaling(t *testing.T) {
	// Create a minimal in-memory queue using sync waiting to verify enqueue marshaling
	var wg sync.WaitGroup
	queueDir := t.TempDir()
	q := diskqueue.New("test-queue", queueDir, 512, 0, 1000, 100, time.Second, func(lvl diskqueue.LogLevel, f string, args ...interface{}) {})
	defer func() { _ = q.Close() }()

	meta := QueueMeta{ProjectId: 10, JobId: 20, JobWebUrl: "http://test", JobName: "test-job"}
	enqueueItem(q, QueueItemJobTrace, meta, &wg)

	// Verify item was queued
	select {
	case item := <-q.ReadChan():
		var decoded QueueItem
		if err := json.Unmarshal(item, &decoded); err != nil {
			t.Fatalf("failed unmarshaling queue item: %v", err)
		}
		if decoded.Type != QueueItemJobTrace {
			t.Fatalf("expected type %s, got %s", QueueItemJobTrace, decoded.Type)
		}
		if decoded.Meta.ProjectId != 10 {
			t.Fatalf("expected project ID 10, got %d", decoded.Meta.ProjectId)
		}
		wg.Done()
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for queue item")
	}
	wg.Wait()
}

func TestDownloadEnvArtifact_404Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result := DownloadEnvArtifact("session-cookie", srv.URL, "owner/repo", 42)
	if len(result) != 0 {
		t.Fatalf("expected empty result on 404, got %d bytes", len(result))
	}
}

func TestDownloadEnvArtifact_PlainTextResponse(t *testing.T) {
	envContent := []byte("MY_VAR=secret_value\nOTHER=other_value\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the expected query parameter
		if r.URL.Query().Get("file_type") != "dotenv" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(envContent)
	}))
	defer srv.Close()

	result := DownloadEnvArtifact("session-cookie", srv.URL, "owner/repo", 42)
	// Plain text content is detected as unknown file type by filetype.Match,
	// which triggers the "unexpected" error branch, returning empty bytes.
	assert.Empty(t, result, "plain text response should return empty bytes due to unknown filetype")
}

func TestDownloadEnvArtifact_GzipResponse(t *testing.T) {
	envContent := "MY_VAR=secret_value\nOTHER=other_value\n"

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte(envContent))
	if err != nil {
		t.Fatalf("failed to create gzip: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("failed to close gzip: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	result := DownloadEnvArtifact("session-cookie", srv.URL, "owner/repo", 42)
	if string(result) != envContent {
		t.Fatalf("expected decompressed content %q, got %q", envContent, string(result))
	}
}

func TestDownloadEnvArtifact_URLBuildFailure(t *testing.T) {
	// A URL that will cause join to fail or produce an unreachable host
	result := DownloadEnvArtifact("cookie", "://invalid-url", "owner/repo", 1)
	if len(result) != 0 {
		t.Fatalf("expected empty result for bad URL, got %d bytes", len(result))
	}
}
