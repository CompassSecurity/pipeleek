package scan

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestGetJobUrl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("token", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	project := &gitlab.Project{PathWithNamespace: "myorg/myproject"}
	job := &gitlab.Job{ID: 42}

	url := getJobUrl(client, project, job)

	// Should contain the host and job path
	if url == "" {
		t.Fatal("expected non-empty URL")
	}

	expected := "myorg/myproject/-/jobs/42"
	if len(url) < len(expected) {
		t.Fatalf("expected URL to contain %q, got %q", expected, url)
	}

	found := false
	for i := 0; i <= len(url)-len(expected); i++ {
		if url[i:i+len(expected)] == expected {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected URL to contain %q, got %q", expected, url)
	}
}

func TestGetQueueStatus_NilQueue(t *testing.T) {
	// Save original queue state
	original := globQueue
	defer func() { globQueue = original }()

	// When queue is nil, should return 0
	globQueue = nil
	status := GetQueueStatus()
	if status != 0 {
		t.Fatalf("expected 0 when queue is nil, got %d", status)
	}
}

func TestCleanUpIsConcurrentSafe(t *testing.T) {
	queueDir := t.TempDir()
	queue, filename := setupQueue(&ScanOptions{QueueFolder: queueDir})

	cleanupMu.Lock()
	originalQueue, originalFilename, originalDone := globQueue, queueFileName, cleanupDone
	globQueue, queueFileName, cleanupDone = queue, filename, false
	cleanupMu.Unlock()
	t.Cleanup(func() {
		cleanupMu.Lock()
		globQueue, queueFileName, cleanupDone = originalQueue, originalFilename, originalDone
		cleanupMu.Unlock()
	})

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			<-start
			cleanUp()
		}()
	}
	close(start)
	wg.Wait()
	cleanUp()

	entries, err := os.ReadDir(queueDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected cleanup to remove queue files, found %v", entries)
	}
}
