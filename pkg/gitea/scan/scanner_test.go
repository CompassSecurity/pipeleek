package gitea

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/hashicorp/go-retryablehttp"
)

// giteaMockServer returns an httptest.Server that satisfies the Gitea SDK's
// version check on NewClient (GET /api/v1/version → {"version":"1.20.0"}).
func giteaMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"1.20.0"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestInitializeOptions_SDKClientInjected(t *testing.T) {
	srv := giteaMockServer(t)

	opts, err := InitializeOptions(
		"test-token", srv.URL,
		"", "", "", "100Mb",
		false, false, false,
		0, 0, 4, []string{}, 30*time.Second,
	)
	if err != nil {
		t.Fatalf("InitializeOptions returned error: %v", err)
	}

	if opts.Client == nil {
		t.Fatal("expected Gitea SDK client to be non-nil")
	}
	if opts.HttpClient == nil {
		t.Fatal("expected HttpClient to be non-nil")
	}
}

func TestInitializeOptions_AuthHeaderInHttpClient(t *testing.T) {
	srv := giteaMockServer(t)

	opts, err := InitializeOptions(
		"my-token", srv.URL,
		"", "", "", "100Mb",
		false, false, false,
		0, 0, 4, []string{}, 30*time.Second,
	)
	if err != nil {
		t.Fatalf("InitializeOptions returned error: %v", err)
	}

	// Auth header should be in the HeaderRoundTripper wrapping the transport.
	hrt, ok := opts.HttpClient.HTTPClient.Transport.(*httpclient.HeaderRoundTripper)
	if !ok {
		t.Fatalf("expected *httpclient.HeaderRoundTripper transport, got %T", opts.HttpClient.HTTPClient.Transport)
	}
	if hrt.Headers["Authorization"] != "token my-token" {
		t.Errorf("expected Authorization header 'token my-token', got %q", hrt.Headers["Authorization"])
	}
}

func TestInitializeOptions_CookiePathSetsJar(t *testing.T) {
	srv := giteaMockServer(t)

	opts, err := InitializeOptions(
		"my-token", srv.URL,
		"", "", "mycookie", "100Mb",
		false, false, false,
		0, 0, 4, []string{}, 30*time.Second,
	)
	if err != nil {
		t.Fatalf("InitializeOptions returned error: %v", err)
	}

	if opts.HttpClient.HTTPClient.Jar == nil {
		t.Error("expected cookie jar to be set when cookie is provided")
	}
}

func TestInitializeOptions_NoTransportMutation(t *testing.T) {
	// Verify no post-hoc mutation of the transport occurs: the transport on the
	// retryable client must be a *httpclient.HeaderRoundTripper wrapping a
	// *http.Transport — not a bare AuthTransport wrapping http.DefaultTransport.
	srv := giteaMockServer(t)

	opts, err := InitializeOptions(
		"tok", srv.URL,
		"", "", "", "100Mb",
		false, false, false,
		0, 0, 4, []string{}, 30*time.Second,
	)
	if err != nil {
		t.Fatalf("InitializeOptions returned error: %v", err)
	}

	hrt, ok := opts.HttpClient.HTTPClient.Transport.(*httpclient.HeaderRoundTripper)
	if !ok {
		t.Fatalf("transport should be HeaderRoundTripper, got %T", opts.HttpClient.HTTPClient.Transport)
	}
	if _, isAuthTransport := hrt.Next.(*AuthTransport); isAuthTransport {
		t.Error("AuthTransport must not be used as Next transport; expected *http.Transport from Pipeleek client")
	}
	if _, isHttpTransport := hrt.Next.(*http.Transport); !isHttpTransport {
		t.Errorf("expected *http.Transport as inner transport, got %T", hrt.Next)
	}
}

func TestInitializeOptions_TLSReflectsGlobalConfig(t *testing.T) {
	httpclient.SetInsecureSkipVerify(false)
	t.Cleanup(func() { httpclient.SetInsecureSkipVerify(true) })

	srv := giteaMockServer(t)

	opts, err := InitializeOptions(
		"tok", srv.URL,
		"", "", "", "100Mb",
		false, false, false,
		0, 0, 4, []string{}, 30*time.Second,
	)
	if err != nil {
		t.Fatalf("InitializeOptions returned error: %v", err)
	}

	hrt := opts.HttpClient.HTTPClient.Transport.(*httpclient.HeaderRoundTripper)
	tr, ok := hrt.Next.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", hrt.Next)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=false to be reflected from Pipeleek global config")
	}
}

func TestInitializeOptions_InvalidURL(t *testing.T) {
	_, err := InitializeOptions(
		"tok", "not-a-url",
		"", "", "", "100Mb",
		false, false, false,
		0, 0, 4, []string{}, 30*time.Second,
	)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// compile-time check
var _ *retryablehttp.Client = (*retryablehttp.Client)(nil)
