package httpclient

import (
	"net/http"
	"testing"
	"time"
)

func TestGetPipeleekHTTPClient(t *testing.T) {
	t.Run("client without cookies", func(t *testing.T) {
		client := GetPipeleekHTTPClient("", nil, nil)
		if client == nil {
			t.Fatal("Expected non-nil client")
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
		if client.Header().Get("User-Agent") != "test-agent" {
			t.Errorf("Expected User-Agent header to be 'test-agent', got %q", client.Header().Get("User-Agent"))
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
		if client.CookieJar() == nil {
			t.Error("Expected cookie jar to be set")
		}
	})

	t.Run("check retry conditions", func(t *testing.T) {
		client := GetPipeleekHTTPClient("", nil, nil)

		// Resty built-in defaults are enabled instead of a custom condition
		if !client.IsRetryDefaultConditions() {
			t.Error("Expected Resty default retry conditions to be enabled")
		}

		// No custom retry conditions should be registered
		if len(client.RetryConditions()) != 0 {
			t.Error("Expected no custom retry conditions — defaults handle 429/5xx/errors")
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
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:8888")
		SetIgnoreProxy(true)

		client := GetPipeleekHTTPClient("", nil, nil)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}

		tr, err := client.HTTPTransport()
		if err != nil {
			t.Fatalf("Expected *http.Transport, got error: %v", err)
		}

		if tr.Proxy != nil {
			t.Error("Expected Proxy to be nil when ignoreProxy is true")
		}
	})

	t.Run("proxy is used when SetIgnoreProxy is false", func(t *testing.T) {
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:8888")
		SetIgnoreProxy(false)

		client := GetPipeleekHTTPClient("", nil, nil)
		if client == nil {
			t.Fatal("Expected non-nil client")
		}

		tr, err := client.HTTPTransport()
		if err != nil {
			t.Fatalf("Expected *http.Transport, got error: %v", err)
		}

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
		tr, err := client.HTTPTransport()
		if err != nil {
			t.Fatalf("Expected *http.Transport, got error: %v", err)
		}
		if !tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected InsecureSkipVerify to be true")
		}
	})

	t.Run("can be disabled to enforce TLS verification", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetInsecureSkipVerify(false)
		client := GetPipeleekHTTPClient("", nil, nil)
		tr, err := client.HTTPTransport()
		if err != nil {
			t.Fatalf("Expected *http.Transport, got error: %v", err)
		}
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
		if client.Timeout() != 0 {
			t.Errorf("Expected zero timeout, got %v", client.Timeout())
		}
	})

	t.Run("non-zero timeout is set on the client", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		want := 30 * time.Second
		SetHTTPTimeout(want)
		client := GetPipeleekHTTPClient("", nil, nil)
		if client.Timeout() != want {
			t.Errorf("Expected timeout %v, got %v", want, client.Timeout())
		}
	})
}

func TestSetProxy(t *testing.T) {
	restore := saveAndRestoreConfig(t)
	defer restore()

	t.Run("valid SOCKS5 proxy sets a dial function on the transport", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetProxy("socks5://127.0.0.1:1080")
		tr := GetPipeleekTransport()
		if tr.DialContext == nil && tr.Dial == nil { //nolint:staticcheck
			t.Error("Expected DialContext or Dial to be set for SOCKS5 proxy")
		}
	})

	t.Run("valid HTTP proxy sets Proxy on the transport", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetProxy("http://127.0.0.1:8080")
		tr := GetPipeleekTransport()
		if tr.Proxy == nil {
			t.Error("Expected Proxy to be set for HTTP proxy")
		}
	})

	t.Run("empty proxy clears the setting", func(t *testing.T) {
		restore2 := saveAndRestoreConfig(t)
		defer restore2()
		SetProxy("")
		// With no explicit proxy configured, the HTTP Proxy field must be nil.
		// DialContext may be the default dialer inherited from http.DefaultTransport.
		tr := GetPipeleekTransport()
		if tr.Proxy != nil {
			t.Error("Expected Proxy to be nil when no proxy is configured")
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
