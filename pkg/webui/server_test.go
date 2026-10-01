package webui

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	if strings.Contains(body, "/api/findings") || strings.Contains(body, "loadFindings") {
		t.Fatal("expected the findings page to rely on SSE instead of the JSON snapshot endpoint")
	}
	if !strings.Contains(body, `viewBox="0 0 375 375"`) {
		t.Fatal("expected the embedded enum report logo in the navbar")
	}
	if !strings.Contains(body, "table-layout: fixed") || strings.Contains(body, "width: 8%; white-space: nowrap") {
		t.Fatal("expected findings table columns to stay within the table width")
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
