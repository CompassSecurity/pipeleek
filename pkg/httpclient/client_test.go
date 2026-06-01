package httpclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHeaderRoundTripper_RoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.Header.Get("Custom-Header")))
	}))
	defer server.Close()

	tests := []struct {
		name          string
		headers       map[string]string
		requestHeader map[string]string
		wantHeader    string
	}{
		{
			name:          "add default header when not present",
			headers:       map[string]string{"Custom-Header": "default-value"},
			requestHeader: map[string]string{},
			wantHeader:    "default-value",
		},
		{
			name:          "preserve existing request header",
			headers:       map[string]string{"Custom-Header": "default-value"},
			requestHeader: map[string]string{"Custom-Header": "request-value"},
			wantHeader:    "request-value",
		},
		{
			name:          "nil headers map",
			headers:       nil,
			requestHeader: map[string]string{},
			wantHeader:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hrt := &HeaderRoundTripper{
				Headers: tt.headers,
				Next:    http.DefaultTransport,
			}

			client := &http.Client{
				Transport: hrt,
			}

			req, err := http.NewRequest("GET", server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			for k, v := range tt.requestHeader {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = resp.Body.Close()
			}()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if string(body) != tt.wantHeader {
				t.Errorf("Expected header value %q, got %q", tt.wantHeader, string(body))
			}
		})
	}
}

func TestGetPipeleekHTTPClient(t *testing.T) {
	t.Run("client without cookies", func(t *testing.T) {
		client := GetPipeleekHTTPClient("", nil, nil)
		if client == nil {
			t.Fatal("Expected non-nil client")
			return
		}
		if client.Logger != nil {
			t.Error("Expected logger to be nil")
		}
	})

	t.Run("client with default headers", func(t *testing.T) {
		headers := map[string]string{
			"User-Agent": "test-agent",
		}
		client := GetPipeleekHTTPClient("", nil, headers)
		if client == nil {
			t.Fatal("Expected non-nil client")
			return
		}

		hrt, ok := client.HTTPClient.Transport.(*HeaderRoundTripper)
		if !ok {
			t.Fatal("Expected HeaderRoundTripper transport")
		}

		if hrt.Headers["User-Agent"] != "test-agent" {
			t.Errorf("Expected User-Agent header to be 'test-agent', got %q", hrt.Headers["User-Agent"])
		}
	})

	t.Run("client with cookies", func(t *testing.T) {
		cookies := []*http.Cookie{
			{Name: "session", Value: "abc123"},
		}
		client := GetPipeleekHTTPClient("http://example.com", cookies, nil)
		if client == nil {
			t.Fatal("Expected non-nil client")
			return
		}
		if client.HTTPClient.Jar == nil {
			t.Error("Expected cookie jar to be set")
		}
	})

	t.Run("check retry function", func(t *testing.T) {
		client := GetPipeleekHTTPClient("", nil, nil)

		shouldRetry, _ := client.CheckRetry(nil, &http.Response{StatusCode: 429}, nil)
		if !shouldRetry {
			t.Error("Expected to retry on 429 status")
		}

		shouldRetry, _ = client.CheckRetry(nil, &http.Response{StatusCode: 500}, nil)
		if !shouldRetry {
			t.Error("Expected to retry on 500 status")
		}

		shouldRetry, _ = client.CheckRetry(nil, &http.Response{StatusCode: 501}, nil)
		if shouldRetry {
			t.Error("Expected NOT to retry on 501 status")
		}

		shouldRetry, _ = client.CheckRetry(nil, &http.Response{StatusCode: 200}, nil)
		if shouldRetry {
			t.Error("Expected NOT to retry on 200 status")
		}

		shouldRetry, _ = client.CheckRetry(nil, nil, nil)
		if shouldRetry {
			t.Error("Expected NOT to retry with nil response")
		}

		shouldRetry, _ = client.CheckRetry(nil, nil, http.ErrServerClosed)
		if !shouldRetry {
			t.Error("Expected to retry on error")
		}
	})
}

func TestSetIgnoreProxy(t *testing.T) {
	// Save original value
	originalIgnoreProxy := ignoreProxy.Load()
	defer func() {
		ignoreProxy.Store(originalIgnoreProxy)
	}()

	t.Run("SetIgnoreProxy sets the flag", func(t *testing.T) {
		SetIgnoreProxy(true)
		if !ignoreProxy.Load() {
			t.Error("Expected ignoreProxy to be true")
		}
		SetIgnoreProxy(false)
		if ignoreProxy.Load() {
			t.Error("Expected ignoreProxy to be false")
		}
	})

	t.Run("proxy is ignored when SetIgnoreProxy is true", func(t *testing.T) {
		// Set HTTP_PROXY using t.Setenv for automatic cleanup
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:8888")

		// Set ignoreProxy to true
		SetIgnoreProxy(true)

		client := GetPipeleekHTTPClient("", nil, nil)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}

		// Get the transport
		hrt, ok := client.HTTPClient.Transport.(*HeaderRoundTripper)
		if !ok {
			t.Fatal("Expected HeaderRoundTripper transport")
		}

		tr, ok := hrt.Next.(*http.Transport)
		if !ok {
			t.Fatal("Expected http.Transport as next transport")
		}

		// When ignoreProxy is true, Proxy should not be set
		if tr.Proxy != nil {
			t.Error("Expected Proxy to be nil when ignoreProxy is true")
		}
	})

	t.Run("proxy is used when SetIgnoreProxy is false", func(t *testing.T) {
		// Set HTTP_PROXY using t.Setenv for automatic cleanup
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:8888")

		// Set ignoreProxy to false
		SetIgnoreProxy(false)

		client := GetPipeleekHTTPClient("", nil, nil)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}

		// Get the transport
		hrt, ok := client.HTTPClient.Transport.(*HeaderRoundTripper)
		if !ok {
			t.Fatal("Expected HeaderRoundTripper transport")
		}

		tr, ok := hrt.Next.(*http.Transport)
		if !ok {
			t.Fatal("Expected http.Transport as next transport")
		}

		// When ignoreProxy is false and HTTP_PROXY is set, Proxy should be set
		if tr.Proxy == nil {
			t.Error("Expected Proxy to be set when ignoreProxy is false and HTTP_PROXY is set")
		}
	})
}

// saveAndRestoreConfig saves the current global config and returns a cleanup function.
func saveAndRestoreConfig(t *testing.T) func() {
	t.Helper()
	configMu.RLock()
	saved := globalConfig
	configMu.RUnlock()
	return func() {
		configMu.Lock()
		globalConfig = saved
		configMu.Unlock()
	}
}

func TestSetInsecureSkipVerify(t *testing.T) {
	restore := saveAndRestoreConfig(t)
	defer restore()

	t.Run("default is true (skip verification)", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetInsecureSkipVerify(true)
		client := GetPipeleekHTTPClient("", nil, nil)
		hrt := client.HTTPClient.Transport.(*HeaderRoundTripper)
		tr := hrt.Next.(*http.Transport)
		if !tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected InsecureSkipVerify to be true")
		}
	})

	t.Run("can be disabled to enforce TLS verification", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetInsecureSkipVerify(false)
		client := GetPipeleekHTTPClient("", nil, nil)
		hrt := client.HTTPClient.Transport.(*HeaderRoundTripper)
		tr := hrt.Next.(*http.Transport)
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected InsecureSkipVerify to be false")
		}
	})

	t.Run("GetPipeleekTransport reflects the setting", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetInsecureSkipVerify(false)
		tr := GetPipeleekTransport()
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected GetPipeleekTransport InsecureSkipVerify to be false")
		}
	})
}

func TestSetHTTPTimeout(t *testing.T) {
	restore := saveAndRestoreConfig(t)
	defer restore()

	t.Run("zero timeout means no timeout", func(t *testing.T) {
		SetHTTPTimeout(0)
		client := GetPipeleekHTTPClient("", nil, nil)
		if client.HTTPClient.Timeout != 0 {
			t.Errorf("Expected zero timeout, got %v", client.HTTPClient.Timeout)
		}
	})

	t.Run("non-zero timeout is set on the underlying client", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		want := 30 * time.Second
		SetHTTPTimeout(want)
		client := GetPipeleekHTTPClient("", nil, nil)
		if client.HTTPClient.Timeout != want {
			t.Errorf("Expected timeout %v, got %v", want, client.HTTPClient.Timeout)
		}
	})
}

func TestSetSOCKSProxy(t *testing.T) {
	restore := saveAndRestoreConfig(t)
	defer restore()

	t.Run("valid SOCKS5 proxy sets a dial function on the transport", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetSOCKSProxy("socks5://127.0.0.1:1080")
		tr := GetPipeleekTransport()
		if tr.DialContext == nil && tr.Dial == nil { //nolint:staticcheck
			t.Error("Expected DialContext or Dial to be set for SOCKS proxy")
		}
	})

	t.Run("empty SOCKS proxy clears the setting", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetSOCKSProxy("")
		// With no SOCKS proxy, transport should have no dialer set and use HTTP_PROXY if any
		tr := GetPipeleekTransport()
		if tr.DialContext != nil {
			t.Error("Expected DialContext to be nil when no SOCKS proxy is configured")
		}
	})
}

func TestGetPipeleekTransport(t *testing.T) {
	restore := saveAndRestoreConfig(t)
	defer restore()

	t.Run("returns non-nil transport", func(t *testing.T) {
		tr := GetPipeleekTransport()
		if tr == nil {
			t.Fatal("Expected non-nil transport")
		}
	})

	t.Run("transport TLS config matches InsecureSkipVerify setting", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetInsecureSkipVerify(true)
		tr := GetPipeleekTransport()
		if !tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected InsecureSkipVerify true on transport")
		}
		SetInsecureSkipVerify(false)
		tr = GetPipeleekTransport()
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected InsecureSkipVerify false on transport")
		}
	})
}
