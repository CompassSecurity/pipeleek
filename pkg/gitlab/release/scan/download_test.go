package scan

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadCredentials(t *testing.T) {
	var received []string
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.Header.Get("PRIVATE-TOKEN"))
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Cookie"))
		_, _ = w.Write([]byte("external"))
	}))
	defer external.Close()
	instance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-token", r.Header.Get("PRIVATE-TOKEN"))
		assert.Empty(t, r.Header.Get("Authorization"))
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, external.URL, http.StatusFound)
			return
		}
		if r.URL.Path == "/internal-redirect" {
			http.Redirect(w, r, "/asset", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("internal"))
	}))
	defer instance.Close()
	base, err := url.Parse(instance.URL)
	require.NoError(t, err)
	for _, target := range []string{instance.URL, external.URL, instance.URL + "/redirect", instance.URL + "/internal-redirect"} {
		_, err := downloadAsset(target, base, "test-token", 100)
		require.NoError(t, err)
	}
	assert.Equal(t, []string{"", ""}, received)
}

func TestDownloadLimitsAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		chunk  bool
		status int
		want   error
	}{
		{"exact", "12345", false, 200, nil},
		{"oversize", "123456", false, 200, errAssetTooLarge},
		{"chunked-exact", "12345", true, 200, nil},
		{"chunked-oversize", "123456", true, 200, errAssetTooLarge},
		{"denied", "123", false, 403, errAssetUnavailable},
		{"not-found", "123", false, 404, errAssetUnavailable},
		{"unauthorized", "123", false, 401, errors.New("HTTP 401")},
		{"partial", "123", false, 206, errors.New("HTTP 206")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if tc.chunk {
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			content, err := downloadAsset(srv.URL+"/asset", &url.URL{}, "", 5)
			if tc.want == nil {
				require.NoError(t, err)
				assert.Equal(t, tc.body, string(content))
			} else if errors.Is(tc.want, errAssetTooLarge) {
				assert.ErrorIs(t, err, errAssetTooLarge)
			} else if errors.Is(tc.want, errAssetUnavailable) {
				assert.ErrorIs(t, err, errAssetUnavailable)
			} else {
				require.ErrorContains(t, err, tc.want.Error())
			}
		})
	}
}

func TestDownloadTruncatedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		_, _ = w.Write([]byte("123"))
	}))
	defer srv.Close()
	_, err := downloadAsset(srv.URL+"/asset", &url.URL{}, "", 5)
	require.ErrorContains(t, err, "unexpected EOF")
}

func TestDownloadDowngradeDoesNotLeakToken(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Private-Token"))
		_, _ = w.Write([]byte("asset"))
	}))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-token", r.Header.Get("Private-Token"))
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	base, err := url.Parse(srv.URL)
	require.NoError(t, err)
	content, err := downloadAsset(srv.URL, base, "test-token", 10)
	require.NoError(t, err)
	assert.Equal(t, "asset", string(content))
}

func TestDownloadErrorRedactsQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop?signature=sensitive", http.StatusFound)
	}))
	defer srv.Close()
	_, err := downloadAsset(srv.URL+"/loop?signature=sensitive", &url.URL{}, "", 10)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sensitive")
	assert.Contains(t, err.Error(), "asset request failed")
}

func TestDownloadMalformedRedirectRedactsQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://%invalid?signature=sensitive")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	_, err := downloadAsset(srv.URL+"/asset", &url.URL{}, "", 10)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sensitive")
}

func TestDownloadDoesNotReadOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000000")
		_, _ = fmt.Fprint(w, strings.Repeat("x", 100))
	}))
	defer srv.Close()
	_, err := downloadAsset(srv.URL+"/large", &url.URL{}, "", 10)
	require.ErrorIs(t, err, errAssetTooLarge)
}

func TestSameOrigin(t *testing.T) {
	base, err := url.Parse("https://gitlab.example.com")
	require.NoError(t, err)
	for _, tc := range []struct {
		target string
		same   bool
	}{
		{"https://GITLAB.example.com:443/asset", true},
		{"https://gitlab.example.com/asset", true},
		{"https://gitlab.example.com:8443/asset", false},
		{"https://sub.gitlab.example.com/asset", false},
		{"http://gitlab.example.com/asset", false},
	} {
		target, err := url.Parse(tc.target)
		require.NoError(t, err)
		assert.Equal(t, tc.same, sameOrigin(base, target), tc.target)
	}
}
