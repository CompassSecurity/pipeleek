package webui

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/logging"
)

//go:embed server_browser_test.js
var browserTests string

func TestBrowserLargeFindings(t *testing.T) {
	browser := os.Getenv("PIPELEEK_WEBUI_BROWSER")
	if browser == "" {
		for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
			if path, err := exec.LookPath(name); err == nil {
				browser = path
				break
			}
		}
	}
	if browser == "" {
		t.Skip("Chromium not installed; set PIPELEEK_WEBUI_BROWSER to run browser regression tests")
	}

	s := &Server{token: "browser-fixture", clients: make(map[chan string]struct{})}
	start := time.Now().Add(-time.Hour)
	for i := range 2000 {
		s.handleHit(logging.HitRecord{
			Time:       start.Add(time.Duration(i) * time.Millisecond),
			Type:       []string{"log", "archive"}[i%2],
			Confidence: []string{"verified", "high", "trufflehog"}[i%3],
			RuleName:   fmt.Sprintf("fixture-rule-%04d", i+1),
			Value:      fmt.Sprintf("fixture-value-%04d\n%s", i+1, strings.Repeat("fixture context ", 16)),
			Fields: map[string]interface{}{
				"url":     fmt.Sprintf("https://example.test/jobs/%04d", i+1),
				"project": fmt.Sprintf("project-%02d", i%20),
				"job":     "fixture-job",
			},
		})
	}
	s.Complete()
	app := s.handler()
	results := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test-result" {
			result, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			select {
			case results <- string(result):
			default:
				http.Error(w, "test result already received", http.StatusConflict)
			}
			return
		}
		r.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: s.token})
		if r.URL.Path != "/" {
			app.ServeHTTP(w, r)
			return
		}
		res := httptest.NewRecorder()
		app.ServeHTTP(res, r)
		for key, values := range res.Header() {
			w.Header()[key] = values
		}
		page := strings.Replace(res.Body.String(), "  <script>", `  <script>
window.testNotifications = [];
window.Notification = function(title, options) {
  window.testNotifications.push({ title: title, options: options });
  this.close = function() { if (this.onclose) this.onclose(); };
};
window.Notification.permission = 'granted';
</script><script>`, 1)
		page = strings.Replace(page, "</body>", "<script>"+browserTests+"</script></body>", 1)
		_, _ = fmt.Fprint(w, page)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, browser,
		"--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
		"--disable-background-networking", "--no-proxy-server",
		"--user-data-dir="+filepath.Join(t.TempDir(), "browser"),
		server.URL)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start browser: %v", err)
	}
	exited := make(chan struct{})
	var browserErr error
	go func() {
		browserErr = cmd.Wait()
		close(exited)
	}()
	stop := func() {
		_ = cmd.Process.Kill()
		<-exited
	}
	defer stop()
	select {
	case result := <-results:
		if !strings.HasPrefix(result, "PASS ") {
			t.Fatalf("browser regression failed: %s", result)
		}
		t.Log(result)
	case <-exited:
		t.Fatalf("browser exited before reporting results: %v\n%s", browserErr, output.String())
	case <-ctx.Done():
		stop()
		t.Fatalf("browser test timed out: %v\n%s", ctx.Err(), output.String())
	}
}
