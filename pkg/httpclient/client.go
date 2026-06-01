// Package httpclient provides a centralized HTTP client configuration for pipeleek.
// It offers a retryable HTTP client with cookie support, custom headers, proxy
// configuration, TLS settings, and SOCKS proxy support.
package httpclient

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/proxy"
)

// ignoreProxy controls whether the HTTP_PROXY environment variable should be ignored.
// When set to true, no proxy will be configured even if HTTP_PROXY is set.
// Uses atomic operations for thread-safe access.
var ignoreProxy atomic.Bool

// SetIgnoreProxy sets whether to ignore the HTTP_PROXY environment variable.
// This is useful in environments where HTTP_PROXY is set but should not be used.
func SetIgnoreProxy(ignore bool) {
	ignoreProxy.Store(ignore)
}

// httpClientConfig holds centrally configurable HTTP transport options.
// All fields are safe to read after the mutex is acquired.
type httpClientConfig struct {
	insecureSkipVerify bool
	socksProxyURL      string
	timeout            time.Duration
}

var (
	configMu     sync.RWMutex
	globalConfig = httpClientConfig{
		// Default true: scanning tools routinely target self-hosted instances
		// with self-signed certificates.
		insecureSkipVerify: true,
	}
)

// SetInsecureSkipVerify controls TLS certificate verification for all Pipeleek-managed
// HTTP clients. Defaults to true (skip verification) to support self-hosted targets with
// self-signed certificates. Set to false to enforce certificate validation.
func SetInsecureSkipVerify(skip bool) {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig.insecureSkipVerify = skip
}

// SetSOCKSProxy sets a SOCKS proxy URL (e.g. "socks5://127.0.0.1:1080") for all
// Pipeleek-managed HTTP clients. When non-empty, it takes precedence over HTTP_PROXY.
func SetSOCKSProxy(socksURL string) {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig.socksProxyURL = socksURL
}

// SetHTTPTimeout sets the per-request timeout applied to all Pipeleek-managed HTTP clients.
// A zero value (the default) means no timeout.
func SetHTTPTimeout(d time.Duration) {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig.timeout = d
}

func readGlobalConfig() httpClientConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig
}

// HeaderRoundTripper is an http.RoundTripper that adds default headers to requests.
// Headers are only added if they're not already present in the request.
type HeaderRoundTripper struct {
	Headers map[string]string
	Next    http.RoundTripper
}

// RoundTrip adds default headers when they're not present on the request
// and delegates to the next RoundTripper.
func (hrt *HeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if hrt.Next == nil {
		return nil, http.ErrNotSupported
	}

	if hrt.Headers != nil {
		for k, v := range hrt.Headers {
			if req.Header.Get(k) == "" {
				req.Header.Set(k, v)
			}
		}
	}

	return hrt.Next.RoundTrip(req)
}

// buildTransport constructs an *http.Transport with TLS, proxy, and SOCKS settings
// taken from the provided config snapshot.
func buildTransport(cfg httpClientConfig) *http.Transport {
	// #nosec G402 - InsecureSkipVerify is user-configurable; defaults to true so that
	// scanning tools can reach self-hosted instances with self-signed certificates.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.insecureSkipVerify},
	}

	if cfg.socksProxyURL != "" {
		u, err := url.Parse(cfg.socksProxyURL)
		if err != nil {
			log.Fatal().Err(err).Str("socks_proxy", cfg.socksProxyURL).Msg("Invalid SOCKS proxy URL")
		}
		dialer, err := proxy.FromURL(u, &net.Dialer{})
		if err != nil {
			log.Fatal().Err(err).Str("socks_proxy", cfg.socksProxyURL).Msg("Failed creating SOCKS proxy dialer")
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			tr.DialContext = cd.DialContext
		} else {
			//nolint:staticcheck
			tr.Dial = dialer.Dial
		}
		log.Info().Str("socks_proxy", cfg.socksProxyURL).Msg("Using SOCKS proxy")
		return tr
	}

	if !ignoreProxy.Load() {
		proxyServer, useHttpProxy := os.LookupEnv("HTTP_PROXY")
		if useHttpProxy {
			proxyUrl, err := url.Parse(proxyServer)
			if err != nil {
				log.Fatal().Err(err).Str("HTTP_PROXY", proxyServer).Msg("Invalid Proxy URL in HTTP_PROXY environment variable")
			}
			log.Info().Str("proxy", proxyUrl.String()).Msg("Using HTTP_PROXY")
			tr.Proxy = http.ProxyURL(proxyUrl)
		}
	}

	return tr
}

// GetPipeleekTransport returns a configured *http.Transport using the current global
// client options (TLS, proxy, SOCKS). Use this to inject Pipeleek's transport settings
// into third-party HTTP client libraries (e.g. Resty, go-github) that manage their own
// request lifecycle but should still share the same network configuration.
func GetPipeleekTransport() *http.Transport {
	return buildTransport(readGlobalConfig())
}

// GetPipeleekHTTPClient creates and configures a retryable HTTP client for pipeleek operations.
// It supports:
//   - Cookie jar configuration for session management
//   - Custom default headers
//   - Automatic retry logic for 429 and 5xx errors (except 501)
//   - HTTP proxy support via HTTP_PROXY environment variable (unless SetIgnoreProxy(true) is called)
//   - SOCKS proxy support via SetSOCKSProxy (takes precedence over HTTP_PROXY)
//   - Configurable TLS certificate verification (SetInsecureSkipVerify; defaults to true)
//   - Configurable per-request timeout (SetHTTPTimeout; defaults to no timeout)
//
// Parameters:
//   - cookieUrl: The URL to associate cookies with (required if cookies are provided)
//   - cookies: Optional cookies to add to the jar
//   - defaultHeaders: Optional headers to add to all requests
//
// Returns a configured *retryablehttp.Client ready for use.
func GetPipeleekHTTPClient(cookieUrl string, cookies []*http.Cookie, defaultHeaders map[string]string) *retryablehttp.Client {
	cfg := readGlobalConfig()

	var jar http.CookieJar

	if len(cookies) > 0 {
		var err error
		jar, err = cookiejar.New(nil)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed creating cookie jar")
		}

		urlParsed, err := url.Parse(cookieUrl)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed parsing URL for cookie jar")
		}

		jar.SetCookies(urlParsed, cookies)
	}

	client := retryablehttp.NewClient()
	client.Logger = nil
	client.HTTPClient.Jar = jar

	if cfg.timeout > 0 {
		client.HTTPClient.Timeout = cfg.timeout
	}

	client.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if err != nil {
			log.Error().Err(err).Msg("Retrying HTTP request, error occurred")
			return true, nil
		}

		if resp == nil {
			log.Error().Msg("Retrying HTTP request, no response")
			return false, nil
		}

		if resp.StatusCode == 429 || (resp.StatusCode >= 500 && resp.StatusCode != 501) {
			url := ""
			if resp.Request != nil && resp.Request.URL != nil {
				url = resp.Request.URL.String()
			}
			log.Trace().Str("url", url).Int("statusCode", resp.StatusCode).Msg("Retrying HTTP request")
			return true, nil
		}

		return false, nil
	}

	tr := buildTransport(cfg)
	client.HTTPClient.Transport = &HeaderRoundTripper{Headers: defaultHeaders, Next: tr}
	return client
}
