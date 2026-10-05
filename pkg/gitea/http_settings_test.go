package gitea_test

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	giteaenum "github.com/CompassSecurity/pipeleek/pkg/gitea/enum"
	"github.com/CompassSecurity/pipeleek/pkg/gitea/secrets"
	"github.com/CompassSecurity/pipeleek/pkg/gitea/variables"
	"github.com/CompassSecurity/pipeleek/pkg/gitea/vuln"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveGitea(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v1/version":
		_, _ = w.Write([]byte(`{"version":"1.20.0"}`))
	case "/api/v1/user":
		_, _ = w.Write([]byte(`{"id":1,"login":"testuser"}`))
	case "/api/v1/user/repos", "/api/v1/user/orgs":
		_, _ = w.Write([]byte(`[]`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestCommandsHTTPSettings(t *testing.T) {
	commands := []struct {
		name string
		run  func(string) error
	}{
		{
			name: "enum",
			run: func(url string) error {
				return giteaenum.RunEnum(url, "test-token")
			},
		},
		{
			name: "secrets",
			run: func(url string) error {
				return secrets.ListAllSecrets(secrets.Config{URL: url, Token: "test-token"})
			},
		},
		{
			name: "variables",
			run: func(url string) error {
				return variables.ListAllVariables(variables.Config{URL: url, Token: "test-token"})
			},
		},
	}

	runCommandsHTTPSettings(t, commands)
}

func TestVulnHTTPSettings(t *testing.T) {
	httpclient.SetIgnoreProxy(true)
	t.Cleanup(func() {
		httpclient.SetProxy("")
		httpclient.SetIgnoreProxy(false)
		httpclient.SetInsecureSkipVerify(true)
		httpclient.SetHTTPTimeout(0)
	})
	nist := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer nist.Close()
	t.Setenv("PIPELEEK_NIST_BASE_URL", nist.URL)

	for _, mode := range []string{"explicit proxy", "self-signed TLS", "enforced TLS", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			httpclient.SetProxy("")
			httpclient.SetInsecureSkipVerify(true)
			httpclient.SetHTTPTimeout(0)
			var output bytes.Buffer
			savedLogger := log.Logger
			log.Logger = zerolog.New(&output)
			defer func() { log.Logger = savedLogger }()

			var versionRequests atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/nist" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
					return
				}
				versionRequests.Add(1)
				if mode == "timeout" {
					time.Sleep(100 * time.Millisecond)
				}
				serveGitea(w, r)
			})
			var target *httptest.Server
			if mode == "self-signed TLS" || mode == "enforced TLS" {
				target = httptest.NewTLSServer(handler)
			} else {
				target = httptest.NewServer(handler)
			}
			defer target.Close()
			url := target.URL
			switch mode {
			case "explicit proxy":
				httpclient.SetProxy(target.URL)
				t.Setenv("PIPELEEK_NIST_BASE_URL", "http://nist.invalid/nist")
				url = "http://gitea.invalid"
			case "enforced TLS":
				httpclient.SetInsecureSkipVerify(false)
			case "timeout":
				httpclient.SetHTTPTimeout(20 * time.Millisecond)
			}

			vuln.RunCheckVulns(url, "test-token")
			assert.Contains(t, output.String(), "Finished vuln scan")
			if mode == "enforced TLS" || mode == "timeout" {
				assert.Contains(t, output.String(), "Failed creating Gitea client")
				assert.Contains(t, output.String(), `"version":"none"`)
			} else {
				assert.Contains(t, output.String(), `"version":"1.20.0"`)
				assert.NotContains(t, output.String(), "Failed creating Gitea client")
				assert.Positive(t, versionRequests.Load())
			}
		})
	}
}

func runCommandsHTTPSettings(t *testing.T, commands []struct {
	name string
	run  func(string) error
}) {
	t.Helper()
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			httpclient.SetProxy("")
			httpclient.SetIgnoreProxy(true)
			httpclient.SetInsecureSkipVerify(true)
			httpclient.SetHTTPTimeout(0)
			t.Cleanup(func() {
				httpclient.SetProxy("")
				httpclient.SetIgnoreProxy(false)
				httpclient.SetInsecureSkipVerify(true)
				httpclient.SetHTTPTimeout(0)
			})

			t.Run("explicit proxy takes precedence over ignore-proxy", func(t *testing.T) {
				var directRequests, proxyRequests atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					directRequests.Add(1)
					serveGitea(w, r)
				}))
				defer target.Close()
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					proxyRequests.Add(1)
					assert.True(t, r.URL.IsAbs(), "proxy must receive an absolute request URL")
					assert.Equal(t, "token test-token", r.Header.Get("Authorization"))
					serveGitea(w, r)
				}))
				defer proxy.Close()

				httpclient.SetProxy(proxy.URL)
				defer httpclient.SetProxy("")

				require.NoError(t, command.run(target.URL))
				assert.GreaterOrEqual(t, proxyRequests.Load(), int32(3), "all SDK requests must use the proxy")
				assert.Zero(t, directRequests.Load(), "requests must not bypass the explicit proxy")
			})

			t.Run("TLS verification settings", func(t *testing.T) {
				target := httptest.NewTLSServer(http.HandlerFunc(serveGitea))
				defer target.Close()

				httpclient.SetInsecureSkipVerify(true)
				require.NoError(t, command.run(target.URL), "default settings must support self-signed targets")

				httpclient.SetInsecureSkipVerify(false)
				defer httpclient.SetInsecureSkipVerify(true)
				require.Error(t, command.run(target.URL), "enforced verification must reject an untrusted certificate")
			})

			t.Run("HTTP timeout", func(t *testing.T) {
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(100 * time.Millisecond)
					serveGitea(w, r)
				}))
				defer target.Close()

				httpclient.SetHTTPTimeout(10 * time.Millisecond)
				defer httpclient.SetHTTPTimeout(0)
				err := command.run(target.URL)
				require.Error(t, err)
				var netErr net.Error
				require.True(t, errors.As(err, &netErr), "expected a network timeout, got %v", err)
				assert.True(t, netErr.Timeout())
			})
		})
	}
}
