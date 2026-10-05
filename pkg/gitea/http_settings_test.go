package gitea_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	giteaenum "github.com/CompassSecurity/pipeleek/pkg/gitea/enum"
	"github.com/CompassSecurity/pipeleek/pkg/gitea/secrets"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
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
	}

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
