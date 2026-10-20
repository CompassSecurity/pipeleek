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

func downloadAsset(u, base *url.URL, token string, limit int64) ([]byte, error) {
	client := httpclient.GetPipeleekStandardHTTPClient()
	defer client.CloseIdleConnections()
	authorize := func(req *http.Request) {
		req.Header.Del("PRIVATE-TOKEN")
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		req.Header.Del("Referer")
		if sameOrigin(base, req.URL) {
			req.Header.Set("PRIVATE-TOKEN", token)
		}
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many asset redirects")
		}
		if err := validateAssetURL(req.URL); err != nil {
			return err
		}
		if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme == "http" {
			return errors.New("asset redirect downgrades HTTPS to HTTP")
		}
		authorize(req)
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("cannot create asset request")
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

func validateAssetURL(u *url.URL) error {
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("asset URL must use HTTP(S) and include a host")
	}
	if u.User != nil {
		return errors.New("asset URL must not contain user credentials")
	}
	return nil
}

func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

func resolveAssetURL(base *url.URL, raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("empty asset URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid asset URL")
	}
	u = base.ResolveReference(u)
	if err := validateAssetURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

// Asset URLs can contain signed query parameters; never include those in output.
func displayURL(u *url.URL) string {
	safe := *u
	safe.User = nil
	safe.RawQuery = ""
	safe.ForceQuery = false
	safe.Fragment = ""
	return safe.String()
}
