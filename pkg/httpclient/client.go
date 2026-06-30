// Package httpclient provides a centralized HTTP client configuration for pipeleek.
// It offers a retryable HTTP client with cookie support, custom headers, proxy
// configuration, TLS settings, and SOCKS proxy support.
package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/proxy"
	"resty.dev/v3"
)

// ignoreProxy controls whether the HTTP_PROXY environment variable should be ignored.
var ignoreProxy atomic.Bool

func SetIgnoreProxy(ignore bool) {
	ignoreProxy.Store(ignore)
}

// httpClientConfig holds centrally configurable HTTP transport options.
type httpClientConfig struct {
	insecureSkipVerify bool
	proxyURL           string
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

// SetProxy sets a proxy URL for all Pipeleek-managed HTTP clients. Accepts both
// HTTP ("http://host:port") and SOCKS5 ("socks5://host:port") URLs. When non-empty,
// it takes precedence over the HTTP_PROXY environment variable.
func SetProxy(proxyURL string) {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig.proxyURL = proxyURL
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

// buildTransport constructs an *http.Transport with TLS, proxy, and SOCKS settings
// taken from the provided config snapshot. It clones http.DefaultTransport so that
// all sane defaults (dial timeout, TLS-handshake timeout, keep-alive, idle-connection
// limits) are inherited before Pipeleek-specific overrides are applied.
func buildTransport(cfg httpClientConfig) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// We manage proxy / SOCKS ourselves below; do not inherit ProxyFromEnvironment.
	tr.Proxy = nil
	// #nosec G402 - InsecureSkipVerify is user-configurable; defaults to true so that
	// scanning tools can reach self-hosted instances with self-signed certificates.
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.insecureSkipVerify}

	if cfg.proxyURL != "" {
		u, err := url.Parse(cfg.proxyURL)
		if err != nil {
			log.Fatal().Err(err).Str("proxy", cfg.proxyURL).Msg("Invalid proxy URL")
		}
		switch u.Scheme {
		case "socks5", "socks5h":
			// Use the configured timeout for the dialer so that unreachable SOCKS proxies
			// do not cause indefinite hangs. Fall back to 30 s when no timeout is set.
			dialTimeout := cfg.timeout
			if dialTimeout <= 0 {
				dialTimeout = 30 * time.Second
			}
			dialer, err := proxy.FromURL(u, &net.Dialer{Timeout: dialTimeout})
			if err != nil {
				log.Fatal().Err(err).Str("proxy", cfg.proxyURL).Msg("Failed creating SOCKS proxy dialer")
			}
			if cd, ok := dialer.(proxy.ContextDialer); ok {
				tr.DialContext = cd.DialContext
			} else {
				//nolint:staticcheck
				tr.Dial = dialer.Dial
			}
			log.Info().Str("proxy", cfg.proxyURL).Msg("Using SOCKS proxy")
		default:
			tr.Proxy = http.ProxyURL(u)
			log.Info().Str("proxy", cfg.proxyURL).Msg("Using HTTP proxy")
		}
		return tr
	}

	if !ignoreProxy.Load() {
		tr.Proxy = http.ProxyFromEnvironment
	}

	if cfg.timeout > 0 {
		tr.ResponseHeaderTimeout = cfg.timeout
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

// GetPipeleekStandardHTTPClient creates a standard-library HTTP client with Pipeleek's transport settings.
func GetPipeleekStandardHTTPClient() *http.Client {
	cfg := readGlobalConfig()
	client := &http.Client{Transport: buildTransport(cfg)}
	if cfg.timeout > 0 {
		client.Timeout = cfg.timeout
	}
	return client
}

// GetPipeleekHTTPClient creates a Resty HTTP client applying the global TLS, proxy, retry, and timeout settings.
func GetPipeleekHTTPClient(cookieUrl string, cookies []*http.Cookie, defaultHeaders map[string]string) *resty.Client {
	cfg := readGlobalConfig()

	client := resty.New()

	if len(cookies) > 0 {
		jar, err := cookiejar.New(nil)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed creating cookie jar")
		}
		urlParsed, err := url.Parse(cookieUrl)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed parsing URL for cookie jar")
		}
		jar.SetCookies(urlParsed, cookies)
		client.SetCookieJar(jar)
	}

	if len(defaultHeaders) > 0 {
		client.SetHeaders(defaultHeaders)
	}

	if cfg.timeout > 0 {
		client.SetTimeout(cfg.timeout)
		client.Client().Timeout = cfg.timeout
	}

	client.SetTransport(buildTransport(cfg))

	client.SetRetryCount(4)
	client.SetRetryWaitTime(1 * time.Second)
	client.SetRetryMaxWaitTime(30 * time.Second)
	client.SetRetryDefaultConditions(true)
	client.AddRetryHooks(func(r *resty.Response, err error) {
		if err != nil {
			log.Error().Err(err).Msg("Retrying HTTP request, error occurred")
			return
		}
		if r == nil {
			return
		}
		reqURL := ""
		if r.RawResponse != nil && r.RawResponse.Request != nil && r.RawResponse.Request.URL != nil {
			reqURL = r.RawResponse.Request.URL.String()
		}
		log.Trace().Str("url", reqURL).Int("statusCode", r.StatusCode()).Msg("Retrying HTTP request")
	})

	return client
}
