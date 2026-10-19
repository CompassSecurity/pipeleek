package rules

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestRulesDownload(t *testing.T) {
	require.True(t, filepath.IsAbs(os.Getenv("PIPELEEK_BINARY")))
	t.Chdir(t.TempDir())
	const fixture = "patterns:\n  - pattern:\n      name: Fixture\n      regex: FIXTURE_[A-Z]+\n      confidence: high\n"
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/mazen160/secrets-patterns-db/master/db/rules-stable.yml", r.URL.Path)
		_, _ = w.Write([]byte(fixture))
	}))
	defer backend.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !assert.Equal(t, http.MethodConnect, r.Method) || !assert.Equal(t, "raw.githubusercontent.com:443", r.Host) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		upstream, err := net.DialTimeout("tcp", backend.Listener.Addr().String(), 5*time.Second)
		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if !assert.NoError(t, err) {
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if !assert.NoError(t, err) {
			return
		}
		go func() { _, _ = io.Copy(upstream, buffer) }()
		_, _ = io.Copy(conn, upstream)
	}))
	defer proxy.Close()
	run := func(extra ...string) (string, error) {
		t.Helper()
		args := append([]string{"rules", "download", "--proxy", proxy.URL, "--http-timeout", "10s"}, extra...)
		stdout, stderr, err := testutil.RunCLI(t, args, nil, 30*time.Second)
		return stdout + stderr, err
	}
	output, err := run()
	require.NoError(t, err, output)
	assert.Contains(t, output, "Downloaded optional rules")
	data, err := os.ReadFile("rules.yml")
	require.NoError(t, err)
	require.Equal(t, fixture, string(data))

	require.NoError(t, os.WriteFile("rules.yml", []byte("original"), 0600))
	output, err = run()
	require.Error(t, err, output)
	assert.Contains(t, output, "--force")
	data, err = os.ReadFile("rules.yml")
	require.NoError(t, err)
	require.Equal(t, "original", string(data))

	output, err = run("--force")
	require.NoError(t, err, output)
	data, err = os.ReadFile("rules.yml")
	require.NoError(t, err)
	require.Equal(t, fixture, string(data))

	output, err = run("--output", "custom.yml")
	require.NoError(t, err, output)
	data, err = os.ReadFile("custom.yml")
	require.NoError(t, err)
	require.Equal(t, fixture, string(data))

	stdout, stderr, err := testutil.RunCLI(t, []string{"config", "gen"}, nil, 30*time.Second)
	require.NoError(t, err, stderr)
	var generated struct {
		Rules struct {
			Download struct {
				Output string
				Force  bool
			}
		}
	}
	require.NoError(t, yaml.Unmarshal([]byte(stdout), &generated))
	require.Equal(t, "rules.yml", generated.Rules.Download.Output)
	require.False(t, generated.Rules.Download.Force)
}
