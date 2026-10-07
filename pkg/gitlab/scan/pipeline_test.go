package scan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestGetAllJobs_StatusScope(t *testing.T) {
	for _, authenticated := range []bool{true, false} {
		for _, filtered := range []bool{true, false} {
			name := "public"
			if authenticated {
				name = "authenticated"
			}
			if filtered {
				name += "/filtered"
			} else {
				name += "/unfiltered"
			}
			t.Run(name, func(t *testing.T) {
				opts := &ScanOptions{Artifacts: true, JobLimit: 2, QueueFolder: t.TempDir()}
				if authenticated {
					opts.GitlabApiToken = "test-token"
				}
				var wantScope []string
				if filtered {
					opts.JobStatuses = []gitlab.BuildStateValue{gitlab.Success, gitlab.Failed}
					wantScope = []string{"success", "failed"}
				}
				var jobPages atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch r.URL.Path {
					case "/api/v4/projects/1/pipelines":
						_, _ = w.Write([]byte(`[{"id":10}]`))
					case "/api/v4/projects/1/jobs", "/api/v4/projects/1/pipelines/10/jobs":
						jobPages.Add(1)
						assert.Equal(t, wantScope, r.URL.Query()["scope[]"])
						if r.URL.Query().Get("page") == "1" {
							w.Header().Set("X-Next-Page", "2")
							_, _ = w.Write([]byte(`[{"id":100,"name":"build"}]`))
						} else {
							assert.Equal(t, "2", r.URL.Query().Get("page"))
							w.Header().Set("X-Next-Page", "3")
							_, _ = w.Write([]byte(`[{"id":101,"name":"test"},{"id":102,"name":"extra"}]`))
						}
					default:
						t.Errorf("unexpected request: %s", r.URL)
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer srv.Close()
				client, err := gitlab.NewClient(opts.GitlabApiToken, gitlab.WithBaseURL(srv.URL))
				require.NoError(t, err)
				queue, _ := setupQueue(opts)
				oldQueue, oldWG := globQueue, waitGroup
				globQueue, waitGroup = queue, new(sync.WaitGroup)
				defer func() {
					assert.NoError(t, queue.Delete())
					globQueue, waitGroup = oldQueue, oldWG
				}()

				getAllJobs(client, &gitlab.Project{ID: 1, PathWithNamespace: "group/project"}, opts)
				assert.Equal(t, int32(2), jobPages.Load(), "job-limit should stop pagination after two matching jobs")
				wantItems := 4
				if authenticated {
					wantItems++
				}
				var traces, artifacts []int
				yamlItems := 0
				for range wantItems {
					select {
					case data := <-queue.ReadChan():
						var item QueueItem
						require.NoError(t, json.Unmarshal(data, &item))
						switch item.Type {
						case QueueItemJobTrace:
							traces = append(traces, item.Meta.JobId)
						case QueueItemArtifact:
							artifacts = append(artifacts, item.Meta.JobId)
						case QueueItemCICDYaml:
							yamlItems++
						}
						waitGroup.Done()
					case <-time.After(2 * time.Second):
						t.Fatal("timed out reading queued items")
					}
				}
				assert.Equal(t, []int{100, 101}, traces)
				assert.Equal(t, traces, artifacts)
				assert.Equal(t, wantItems-4, yamlItems)
			})
		}
	}
}

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
