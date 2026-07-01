package gitea

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
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

	// Auth header should be in Resty's client-level headers.
	if opts.HttpClient.Header().Get("Authorization") != "token my-token" {
		t.Errorf("expected Authorization header 'token my-token', got %q", opts.HttpClient.Header().Get("Authorization"))
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

	if opts.HttpClient.CookieJar() == nil {
		t.Error("expected cookie jar to be set when cookie is provided")
	}
}

func TestInitializeOptions_NoTransportMutation(t *testing.T) {
	// Verify that the transport on the Resty client is Pipeleek's *http.Transport
	// (not an AuthTransport or other wrapper — auth is handled via client headers).
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

	_, err = opts.HttpClient.HTTPTransport()
	if err != nil {
		t.Errorf("expected *http.Transport from Pipeleek client, got error: %v", err)
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

	tr, err := opts.HttpClient.HTTPTransport()
	if err != nil {
		t.Fatalf("expected *http.Transport, got error: %v", err)
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
