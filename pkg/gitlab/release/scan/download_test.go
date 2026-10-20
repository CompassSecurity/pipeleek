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

type testAssetDownloader struct {
	base  *url.URL
	limit int64
}

func (d testAssetDownloader) resolve(raw string) (*url.URL, error) {
	return resolveAssetURL(d.base, raw)
}

func (d testAssetDownloader) download(u *url.URL) ([]byte, error) {
	return downloadAsset(u, d.base, "test-token", d.limit)
}

func testDownloader(t *testing.T, base string, limit int64) testAssetDownloader {
	t.Helper()
	u, err := url.Parse(base)
	require.NoError(t, err)
	return testAssetDownloader{u, limit}
}

func TestDownloadCredentials(t *testing.T) {
	var received []string
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.Header.Get("PRIVATE-TOKEN"))
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Cookie"))
		assert.Empty(t, r.Header.Get("Referer"))
		_, _ = w.Write([]byte("external"))
	}))
	defer external.Close()
	instance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-token", r.Header.Get("PRIVATE-TOKEN"))
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, external.URL, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("internal"))
	}))
	defer instance.Close()
	d := testDownloader(t, instance.URL, 100)
	for _, target := range []string{instance.URL, external.URL, instance.URL + "/redirect"} {
		u, err := d.resolve(target)
		require.NoError(t, err)
		_, err = d.download(u)
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
			d := testDownloader(t, srv.URL, 5)
			u, err := d.resolve("/asset")
			require.NoError(t, err)
			content, err := d.download(u)
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
	d := testDownloader(t, srv.URL, 5)
	u, err := d.resolve("/asset")
	require.NoError(t, err)
	_, err = d.download(u)
	require.ErrorContains(t, err, "unexpected EOF")
}

func TestAssetURLs(t *testing.T) {
	d := testDownloader(t, "https://gitlab.example.com/subpath/", 10)
	u, err := d.resolve("uploads/asset?token=sensitive#fragment")
	require.NoError(t, err)
	assert.Equal(t, "https://gitlab.example.com/subpath/uploads/asset", displayURL(u))
	for _, raw := range []string{"", "ftp://example.com/file", "file:///etc/passwd", "https://user:password@example.com/file", "%invalid"} {
		_, err := d.resolve(raw)
		require.Error(t, err, raw)
		assert.NotContains(t, err.Error(), "password")
	}
	for _, tc := range []struct {
		target string
		same   bool
	}{
		{"https://GITLAB.example.com:443/other", true},
		{"https://gitlab.example.com:8443/other", false},
		{"https://sub.gitlab.example.com/file", false},
		{"http://gitlab.example.com/file", false},
	} {
		target, err := url.Parse(tc.target)
		require.NoError(t, err)
		assert.Equal(t, tc.same, sameOrigin(d.base, target))
	}
}

func TestRedirectPolicy(t *testing.T) {
	for _, target := range []string{"http://example.com/file", "ftp://example.com/file"} {
		t.Run(target, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusFound)
			}))
			defer srv.Close()
			d := testDownloader(t, srv.URL, 10)
			u, err := d.resolve("/asset")
			require.NoError(t, err)
			_, err = d.download(u)
			require.ErrorContains(t, err, "asset request failed")
		})
	}
}

func TestDownloadErrorRedactsQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop?signature=sensitive", http.StatusFound)
	}))
	defer srv.Close()
	d := testDownloader(t, srv.URL, 10)
	u, err := d.resolve("/loop?signature=sensitive")
	require.NoError(t, err)
	_, err = d.download(u)
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
	d := testDownloader(t, srv.URL, 10)
	u, err := d.resolve("/asset")
	require.NoError(t, err)
	_, err = d.download(u)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sensitive")
}

func TestDownloadDoesNotReadOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000000")
		_, _ = fmt.Fprint(w, strings.Repeat("x", 100))
	}))
	defer srv.Close()
	d := testDownloader(t, srv.URL, 10)
	u, err := d.resolve("/large")
	require.NoError(t, err)
	_, err = d.download(u)
	require.ErrorIs(t, err, errAssetTooLarge)
}
