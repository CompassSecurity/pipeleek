package webui

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/logging"
)

func TestHandleRootSetsSecureAuthCookie(t *testing.T) {
	s := &Server{token: "abc", clients: make(map[chan string]struct{})}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/?token=abc", nil)
	res := httptest.NewRecorder()
	s.handleRoot(res, req)

	if res.Code != http.StatusSeeOther {
		t.Fatalf("expected status %d, got %d", http.StatusSeeOther, res.Code)
	}
	cookies := res.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one auth cookie, got %d", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected Secure, HttpOnly, SameSite=Strict cookie; got %#v", cookie)
	}
}

func TestHandleHitAssignsUniqueIDs(t *testing.T) {
	s := &Server{clients: make(map[chan string]struct{})}
	record := logging.HitRecord{Time: time.Now(), Value: "same-secret", Fields: map[string]interface{}{"ruleName": "same-rule"}}
	s.handleHit(record)
	s.handleHit(record)

	if len(s.findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(s.findings))
	}
	if s.findings[0].ID == s.findings[1].ID {
		t.Fatalf("expected distinct finding IDs, both were %q", s.findings[0].ID)
	}
	if got, want := s.findings[0].TimestampMillis, record.Time.UnixMilli(); got != want {
		t.Errorf("expected precise finding timestamp %d, got %d", want, got)
	}
}

func TestCompletedEventsReplayFindingsAndDone(t *testing.T) {
	startedAt := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	s := &Server{token: "abc", clients: make(map[chan string]struct{}), startedAt: startedAt}
	s.handleHit(logging.HitRecord{Time: time.Now(), Value: "secret"})
	s.Complete()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: "abc"})
	res := httptest.NewRecorder()
	s.handler().ServeHTTP(res, req)

	body := res.Body.String()
	findingIndex := strings.Index(body, "event: finding")
	replayCompleteIndex := strings.Index(body, "event: replay-complete")
	doneIndex := strings.Index(body, "event: done")
	if findingIndex < 0 || replayCompleteIndex <= findingIndex || doneIndex <= replayCompleteIndex {
		t.Fatalf("expected replayed findings, replay completion, then scan completion, got %q", body)
	}
	if !strings.Contains(body[doneIndex:], `"elapsedMillis":`) {
		t.Fatalf("expected completion event to contain server-computed elapsed time, got %q", body[doneIndex:])
	}
}

func TestDoneEventUsesServerCompletionTime(t *testing.T) {
	startedAt := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	s := &Server{
		startedAt:   startedAt,
		completedAt: startedAt.Add(42*time.Second + 135*time.Millisecond),
		completed:   true,
	}

	if got, want := s.doneEventLocked(), "event: done\ndata: {\"elapsedMillis\":42135}\n\n"; got != want {
		t.Fatalf("expected authoritative completion event %q, got %q", want, got)
	}
}

func TestHandleHitDisconnectsOverflowedSSEClient(t *testing.T) {
	s := &Server{clients: make(map[chan string]struct{})}
	client := make(chan string, 1)
	client <- "queued"
	s.clients[client] = struct{}{}
	s.handleHit(logging.HitRecord{Time: time.Now(), Value: "secret"})

	if len(s.clients) != 0 {
		t.Fatal("expected overflowed SSE client to be removed for reconnect and replay")
	}
	if got := <-client; got != "queued" {
		t.Fatalf("expected queued event before closure, got %q", got)
	}
	if _, ok := <-client; ok {
		t.Fatal("expected overflowed SSE client channel to be closed")
	}
}

func TestStartConfiguresReadHeaderTimeout(t *testing.T) {
	server, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	if server.server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("expected 5s ReadHeaderTimeout, got %s", server.server.ReadHeaderTimeout)
	}
}

func TestHandleRootAllowsInlineScript(t *testing.T) {
	s := &Server{token: "abc", clients: make(map[chan string]struct{})}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: "abc"})
	res := httptest.NewRecorder()

	s.handleRoot(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, res.Code)
	}
	body := res.Body.String()
	if !strings.Contains(body, "Live secret findings") {
		t.Fatalf("expected rendered page body, got %q", body)
	}
	if !strings.Contains(body, "No findings yet. Results will appear here as the scan runs.") || !strings.Contains(body, "No findings were detected.") || !strings.Contains(body, "No findings match the current filters.") {
		t.Fatal("expected distinct empty states for an active scan, a completed scan, and filtered results")
	}
	if !strings.Contains(body, "id=\"elapsed-time\"") || !strings.Contains(body, "var elapsedBase = ") || !strings.Contains(body, "window.setInterval(updateElapsedTime, 1000)") {
		t.Fatal("expected elapsed timer element, server-provided baseline, and periodic updates")
	}
	if !strings.Contains(body, `id="notification-threshold-picker"`) || !strings.Contains(body, `aria-multiselectable="false"`) || !strings.Contains(body, `data-value="high-verified" aria-selected="true"`) || !strings.Contains(body, `data-value="none" aria-selected="false"`) || !strings.Contains(body, `class="badge high-verified">high-verified</span>`) || !strings.Contains(body, `id="enable-notifications"`) {
		t.Fatal("expected single-select badge picker with high-verified default, None option, and permission fallback control")
	}
	if strings.Index(body, `id="notification-status"`) < strings.Index(body, `id="notification-threshold-picker"`) {
		t.Fatal("expected notification status to appear after its threshold picker")
	}
	if !strings.Contains(body, "Notification.requestPermission()") || !strings.Contains(body, "function meetsNotificationThreshold") || !strings.Contains(body, "Confidence: ' + (item.confidence || 'unknown')") {
		t.Fatal("expected permission prompting, threshold matching, and non-secret notification text")
	}
	if !strings.Contains(body, "notificationsSince = Date.now(); closeActiveNotifications()") || !strings.Contains(body, "Number(item.timestampMillis)") || !strings.Contains(body, "findingTime < notificationsSince") || !strings.Contains(body, "function closeActiveNotifications()") {
		t.Fatal("expected threshold changes to close and suppress already-queued notifications")
	}
	if !strings.Contains(body, `id="notification-threshold" type="hidden" value="high-verified"`) || strings.Contains(body, "document.cookie") || strings.Contains(body, "localStorage") {
		t.Fatal("expected the notification threshold to reset to high-verified for each new WebUI page")
	}
	if strings.Contains(body, "tableBody.innerHTML") || !strings.Contains(body, "function appendDetailValue") || !strings.Contains(body, "parsed.protocol === 'http:' || parsed.protocol === 'https:'") {
		t.Fatal("expected finding values to render via DOM text APIs with HTTP(S)-only links")
	}
	if strings.Contains(body, "/api/findings") || strings.Contains(body, "loadFindings") {
		t.Fatal("expected the findings page to rely on SSE instead of the JSON snapshot endpoint")
	}
	if !strings.Contains(body, `viewBox="0 0 375 375"`) {
		t.Fatal("expected the embedded enum report logo in the navbar")
	}
	if !strings.Contains(body, "table-layout: fixed") || strings.Contains(body, "width: 8%; white-space: nowrap") {
		t.Fatal("expected findings table columns to stay within the table width")
	}
	if !strings.Contains(body, ".filters { display: flex; flex-wrap: wrap; gap: .75rem; align-items: flex-start; }") || !strings.Contains(body, ".filters > .control-btn { align-self: flex-start; margin-top: 1.5rem; }") {
		t.Fatal("expected filter labels to align at the top while action buttons align with the controls")
	}
	if strings.Count(body, `aria-multiselectable="true"`) != 2 || !strings.Contains(body, `class="badge high-verified">high-verified</span>`) {
		t.Fatal("expected severity and type filters to render badge-style multi-select options")
	}
	if !strings.Contains(body, `id="toggle-full-width"`) || !strings.Contains(body, "main.main-wide") {
		t.Fatal("expected the enum-style full-width toggle")
	}
	if !strings.Contains(body, `id="export-csv"`) || !strings.Contains(body, "function filteredFindings()") || !strings.Contains(body, "fetch('/api/export.csv'") {
		t.Fatal("expected CSV export to send the same filtered findings used by the table")
	}
	csp := res.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("expected CSP to allow inline script, got %q", csp)
	}
}

func TestHandleRootRendersFixedActiveAndCompletedElapsedTimes(t *testing.T) {
	startedAt := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		server      *Server
		now         time.Time
		wantElapsed string
		wantState   string
	}{
		{
			name:        "active scan",
			server:      &Server{token: "abc", startedAt: startedAt},
			now:         startedAt.Add(12*time.Second + 345*time.Millisecond),
			wantElapsed: "12345",
			wantState:   "false",
		},
		{
			name: "completed scan",
			server: &Server{
				token:       "abc",
				startedAt:   startedAt,
				completedAt: startedAt.Add(42*time.Second + 135*time.Millisecond),
				completed:   true,
			},
			now:         startedAt.Add(time.Minute),
			wantElapsed: "42135",
			wantState:   "true",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: "abc"})
			res := httptest.NewRecorder()
			test.server.handleRootAt(res, req, test.now)

			body := res.Body.String()
			elapsedMatch := regexp.MustCompile(`var elapsedBase =\s+(\d+)\s*;`).FindStringSubmatch(body)
			stateMatch := regexp.MustCompile(`completed:\s+(true|false)\s*,`).FindStringSubmatch(body)
			if len(elapsedMatch) < 2 || elapsedMatch[1] != test.wantElapsed || len(stateMatch) < 2 || stateMatch[1] != test.wantState {
				t.Fatalf("expected elapsed baseline %q and completed state %q in rendered page", test.wantElapsed, test.wantState)
			}
		})
	}
}

func TestFindingsJSONEndpointIsRemoved(t *testing.T) {
	s := &Server{token: "abc", clients: make(map[chan string]struct{})}
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	req.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: "abc"})
	res := httptest.NewRecorder()
	s.handler().ServeHTTP(res, req)

	if res.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, res.Code)
	}
}

func TestProtectedRoutesRejectMissingOrInvalidCookies(t *testing.T) {
	routes := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "page", method: http.MethodGet, path: "/"},
		{name: "favicon", method: http.MethodGet, path: "/favicon.svg"},
		{name: "events", method: http.MethodGet, path: "/events"},
		{name: "csv export", method: http.MethodPost, path: "/api/export.csv", body: "[]"},
	}
	credentials := []struct {
		name  string
		value string
	}{
		{name: "missing cookie"},
		{name: "invalid cookie", value: "wrong"},
	}

	for _, credential := range credentials {
		t.Run(credential.name, func(t *testing.T) {
			for _, route := range routes {
				t.Run(route.name, func(t *testing.T) {
					s := &Server{token: "abc", clients: make(map[chan string]struct{})}
					req := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
					if credential.value != "" {
						req.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: credential.value})
					}
					res := httptest.NewRecorder()
					s.handler().ServeHTTP(res, req)
					if res.Code != http.StatusUnauthorized {
						t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, res.Code)
					}
				})
			}
		})
	}
}

func TestEventsAllowValidCookie(t *testing.T) {
	s := &Server{token: "abc", clients: make(map[chan string]struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: "abc"})
	res := httptest.NewRecorder()
	s.handler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, res.Code)
	}
	if got := res.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("expected event stream content type, got %q", got)
	}
}

func TestExportCSVPreservesSpecialValues(t *testing.T) {
	findings := []Finding{
		{
			Time:       "2026-10-01T12:34:56Z",
			Type:       "log",
			Confidence: "high",
			RuleName:   `rule, with "quotes"`,
			Value:      "first line,\r\nsecond line \"quoted\" 雪",
			Details: map[string]string{
				"url": "https://example.test/a?x=1,2",
				"job": "first,\nsecond",
			},
		},
		{
			Time:       "2026-10-01T12:35:00Z",
			Type:       "dotenv",
			Confidence: "low",
			RuleName:   "formula value",
			Value:      "\t=1+1",
		},
	}
	body, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{token: "abc", clients: make(map[chan string]struct{})}
	req := httptest.NewRequest(http.MethodPost, "/api/export.csv", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: "abc"})
	res := httptest.NewRecorder()
	s.handler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, res.Code, res.Body.String())
	}
	if got := res.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/csv") {
		t.Fatalf("expected CSV content type, got %q", got)
	}
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(res.Body.String(), "\ufeff")))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("could not parse exported CSV: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected header and two findings, got %d records", len(records))
	}
	if got, want := records[1][1], findings[0].RuleName; got != want {
		t.Errorf("rule name mismatch: got %q, want %q", got, want)
	}
	if got, want := records[1][2], strings.ReplaceAll(findings[0].Value, "\r\n", "\n"); got != want {
		t.Errorf("secret mismatch: got %q, want %q", got, want)
	}
	if got, want := records[1][4], "job: first,\nsecond; url: https://example.test/a?x=1,2"; got != want {
		t.Errorf("details mismatch: got %q, want %q", got, want)
	}
	if got, want := records[2][2], "'\t=1+1"; got != want {
		t.Errorf("formula-leading secret was not protected: got %q, want %q", got, want)
	}
}
