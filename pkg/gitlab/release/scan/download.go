package scan

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
)

var errAssetTooLarge = errors.New("asset exceeds maximum size")
var errAssetUnavailable = errors.New("asset is forbidden or not found")

func downloadAsset(rawURL string, base *url.URL, token string, limit int64) ([]byte, error) {
	client := httpclient.GetPipeleekStandardHTTPClient()
	defer client.CloseIdleConnections()
	authorize := func(req *http.Request) {
		req.Header.Del("PRIVATE-TOKEN")
		if sameOrigin(base, req.URL) {
			req.Header.Set("PRIVATE-TOKEN", token)
		}
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		authorize(req)
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("invalid asset request URL")
	}
	authorize(req)
	resp, err := client.Do(req)
	if err != nil {
		// Request/redirect errors can include signed URLs; do not log their values.
		return nil, errors.New("asset request failed (connection, URL, or redirect policy)")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return nil, errAssetUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("asset download returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, errAssetTooLarge
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading asset failed: %w", err)
	}
	if int64(len(content)) > limit {
		return nil, errAssetTooLarge
	}
	return content, nil
}

func sameOrigin(a, b *url.URL) bool {
	host := func(u *url.URL) string {
		if u.Scheme == "https" {
			return strings.TrimSuffix(u.Host, ":443")
		}
		return strings.TrimSuffix(u.Host, ":80")
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(host(a), host(b))
}
