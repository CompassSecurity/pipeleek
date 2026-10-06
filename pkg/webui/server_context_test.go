package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gitlabenum "github.com/CompassSecurity/pipeleek/pkg/gitlab/enum"
)

func TestHandleRootRendersSanitizedScanContext(t *testing.T) {
	s := &Server{
		token:   "abc",
		clients: make(map[chan string]struct{}),
		scanContext: ScanContext{
			TargetURL: "https://user:password@example.test/group?access_token=url-secret#fragment",
			Options: []ScanOption{
				{Name: "--token", Value: "api-secret"},
				{Name: "--cookie", Value: "session-secret"},
				{Name: "--password", Value: "password-secret"},
				{Name: "--secrets-verification", Value: "true"},
				{Name: "--search", Value: `<script>alert("x")</script>`},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: "abc"})
	res := httptest.NewRecorder()

	s.handleRoot(res, req)

	body := res.Body.String()
	contextStart := strings.Index(body, `<section class="card scan-context"`)
	if contextStart < 0 {
		t.Fatal("expected scan context section")
	}
	contextEnd := strings.Index(body[contextStart:], `</section>`)
	if contextEnd < 0 {
		t.Fatal("expected scan context section to close")
	}
	contextHTML := body[contextStart : contextStart+contextEnd]
	if heading := strings.Index(body, "Live secret findings"); heading < 0 || contextStart < heading ||
		!strings.Contains(body[contextStart+contextEnd:], `id="summary-cards"`) {
		t.Fatal("expected scan context immediately after the heading and before the findings summary")
	}
	for _, expected := range []string{
		`aria-label="Scan context"`,
		"Target instance",
		"https://example.test/group",
		"Effective scan flags",
		"--token",
		"--cookie",
		"--password",
		"[redacted]",
		`&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;`,
	} {
		if !strings.Contains(contextHTML, expected) {
			t.Errorf("expected scan context to contain %q", expected)
		}
	}
	for _, sensitive := range []string{
		"user:password@",
		"url-secret",
		"fragment",
		"api-secret",
		"session-secret",
		"password-secret",
		"<script>",
	} {
		if strings.Contains(contextHTML, sensitive) {
			t.Errorf("scan context leaked %q", sensitive)
		}
	}
	if !strings.Contains(contextHTML, `<span class="scan-option-name">--secrets-verification</span><span class="scan-option-value">true</span>`) {
		t.Fatal("expected the non-sensitive secrets-verification flag to retain its value")
	}
}

func TestFaviconServesPipeleekLogoWithSVGContentType(t *testing.T) {
	s := &Server{token: "abc", clients: make(map[chan string]struct{})}
	req := httptest.NewRequest(http.MethodGet, "/favicon.svg", nil)
	req.AddCookie(&http.Cookie{Name: "pipeleek-webui-token", Value: "abc"})
	res := httptest.NewRecorder()

	s.handler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, res.Code)
	}
	if got := res.Header().Get("Content-Type"); got != "image/svg+xml; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want SVG content type", got)
	}
	if got, want := res.Body.String(), string(gitlabenum.PipeleekLogoHTML()); got != want {
		t.Fatal("favicon response did not contain the embedded Pipeleek logo")
	}
	if !strings.Contains(pageTemplate, `<link rel="icon" type="image/svg+xml" href="/favicon.svg" />`) {
		t.Fatal("expected page template to link the SVG favicon")
	}
}

func TestSanitizeTargetURLRejectsMalformedOrRelativeURLs(t *testing.T) {
	for _, target := range []string{
		"://broken",
		"/relative/path",
	} {
		if got := sanitizeTargetURL(target); got != "Unavailable" {
			t.Errorf("sanitizeTargetURL(%q) = %q, want Unavailable", target, got)
		}
	}
}
