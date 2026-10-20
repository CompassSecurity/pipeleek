package release_test

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	server   *httptest.Server
	requests func() []testutil.RecordedRequest
}

func newFixture(t *testing.T, links []map[string]any, assetHandler http.HandlerFunc) fixture {
	t.Helper()
	testutil.UseTestRules(t)
	srv, requests, cleanup := testutil.StartMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v4/projects", r.URL.Path == "/api/v4/groups/10/projects":
			_, _ = fmt.Fprint(w, `[{"id":1,"path_with_namespace":"group/project"}]`)
		case strings.HasPrefix(r.URL.Path, "/api/v4/projects/group"):
			_, _ = fmt.Fprint(w, `{"id":1,"path_with_namespace":"group/project"}`)
		case r.URL.Path == "/api/v4/groups/group":
			_, _ = fmt.Fprint(w, `{"id":10}`)
		case r.URL.Path == "/api/v4/projects/1/releases":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"tag_name": "v2", "name": "Release 2", "assets": map[string]any{
					"links": links, "sources": []map[string]string{{"format": "zip", "url": "/source.zip"}, {"format": "tar.gz", "url": "/source.tar.gz"}},
				}},
				{"tag_name": "v1", "name": "Release 1", "assets": map[string]any{"links": links}},
			})
		case r.URL.Path == "/api/v4/projects/1/releases/version/1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "version/1", "name": "Exact release", "assets": map[string]any{"links": links},
			})
		default:
			assetHandler(w, r)
		}
	})
	t.Cleanup(cleanup)
	return fixture{srv, requests}
}

func (f fixture) run(t *testing.T, extra ...string) (string, error) {
	t.Helper()
	args := append([]string{"gl", "release", "scan", "--url", f.server.URL, "--token", "test-token",
		"--secrets-verification=false", "--json"}, extra...)
	stdout, stderr, err := testutil.RunCLI(t, args, nil, 60*time.Second)
	return stdout + stderr, err
}

func links(urls ...string) []map[string]any {
	result := make([]map[string]any, 0, len(urls))
	for i, u := range urls {
		result = append(result, map[string]any{"id": i + 1, "name": fmt.Sprintf("asset-%d", i), "url": u})
	}
	return result
}

func plainAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprint(w, "DATABASE_PASSWORD=releasefixture\n")
}

func TestReleaseScanDefaultAndProjectFilters(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		path string
		want map[string]string
	}{
		{"all", nil, "/api/v4/projects", map[string]string{}},
		{"repo", []string{"--repo", "group/project"}, "/api/v4/projects/group/project", nil},
		{"filters", []string{"--owned", "--member", "--search", "project"}, "/api/v4/projects",
			map[string]string{"owned": "true", "membership": "true", "search": "project"}},
		{"namespace", []string{"--namespace", "group", "--owned", "--search", "project"}, "/api/v4/groups/10/projects",
			map[string]string{"include_subgroups": "true", "owned": "true", "search": "project"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, links("/asset"), plainAsset)
			output, err := f.run(t, tc.args...)
			require.NoError(t, err, output)
			assert.Contains(t, output, `"level":"hit"`)
			assert.Contains(t, output, `"project":"group/project"`)
			for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
				var event struct {
					Level   string `json:"level"`
					Tag     string `json:"tag"`
					Release string `json:"release"`
				}
				require.NoError(t, json.Unmarshal([]byte(line), &event))
				if event.Level == "hit" {
					assert.Contains(t, []string{"v1", "v2"}, event.Tag)
					assert.Equal(t, "Release "+strings.TrimPrefix(event.Tag, "v"), event.Release)
				}
			}
			assert.Contains(t, output, `"asset":"asset-0"`)
			assert.Contains(t, output, `"scannedAssets":2`)
			var matched bool
			for _, req := range f.requests() {
				if req.Path == tc.path {
					matched = true
					assert.Equal(t, "test-token", req.Headers.Get("Private-Token"))
					for k, v := range tc.want {
						assert.Contains(t, req.RawQuery, k+"="+v)
					}
				}
				assert.NotEqual(t, "/source.zip", req.Path)
			}
			assert.True(t, matched, tc.path)
		})
	}
}

func TestReleaseScanExactTagAndLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		tag  string
	}{
		{"limit", []string{"--release-limit", "1"}, "v2"},
		{"tag", []string{"--repo", "group/project", "--tag", "version/1"}, "version/1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, links("/asset"), plainAsset)
			output, err := f.run(t, tc.args...)
			require.NoError(t, err, output)
			assert.Contains(t, output, `"tag":"`+tc.tag+`"`)
			assert.Contains(t, output, `"scannedAssets":1`)
			for _, req := range f.requests() {
				assert.NotContains(t, req.Path, "/v1/")
				if tc.name == "tag" {
					assert.NotEqual(t, "/api/v4/projects/1/releases", req.Path)
				}
			}
		})
	}
}

func zipAsset(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	entry, err := z.Create(name)
	require.NoError(t, err)
	_, err = entry.Write(content)
	require.NoError(t, err)
	require.NoError(t, z.Close())
	return buf.Bytes()
}

func TestReleaseScanSourcesAndNestedArchives(t *testing.T) {
	nested := zipAsset(t, "nested.zip", zipAsset(t, "config.env", []byte("DATABASE_PASSWORD=nestedfixture\n")))
	f := newFixture(t, links("/nested.zip"), func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Private-Token") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/nested.zip":
			_, _ = w.Write(nested)
		case "/source.zip":
			_, _ = w.Write(zipAsset(t, "project/config.env", []byte("JWT_SECRET=sourcefixture\n")))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	output, err := f.run(t, "--release-limit", "1", "--include-sources")
	require.NoError(t, err, output)
	assert.Contains(t, output, "nestedfixture")
	assert.Contains(t, output, "sourcefixture")
	assert.Contains(t, output, `"file":"project/config.env"`)
	assert.Contains(t, output, `"tag":"v2"`)
	assert.Contains(t, output, `"scannedAssets":2`)
	var sources int
	for _, req := range f.requests() {
		if req.Path == "/source.zip" {
			sources++
		}
		assert.NotEqual(t, "/source.tar.gz", req.Path)
	}
	assert.Equal(t, 1, sources)
}

func TestReleaseScanTarAndBinary(t *testing.T) {
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gz)
	text := []byte("ENCRYPTION_KEY=tarfixture\n")
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{Name: "config/secret.env", Size: int64(len(text)), Mode: 0600}))
	_, err := tarWriter.Write(text)
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gz.Close())
	f := newFixture(t, links("/archive.tar.gz", "/binary"), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/binary" {
			header := make([]byte, 64)
			copy(header, "\x7fELF")
			_, _ = w.Write(append(header, []byte("DATABASE_PASSWORD=binaryfixture\n\x00")...))
		} else {
			_, _ = w.Write(archive.Bytes())
		}
	})
	output, err := f.run(t, "--release-limit", "1")
	require.NoError(t, err, output)
	assert.Contains(t, output, "tarfixture")
	assert.Contains(t, output, "binaryfixture")
	assert.Contains(t, output, `"file":"config/secret.env"`)
}

func TestReleaseScanExternalRedirectDoesNotLeakCredentials(t *testing.T) {
	var externalRequests atomic.Int64
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalRequests.Add(1)
		assert.Empty(t, r.Header.Get("Private-Token"))
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Cookie"))
		plainAsset(w, r)
	}))
	defer external.Close()
	f := newFixture(t, links(external.URL+"/direct", "/redirect?signature=do-not-log"), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-token", r.Header.Get("Private-Token"))
		http.Redirect(w, r, external.URL+"/redirected?signature=do-not-log", http.StatusFound)
	})
	output, err := f.run(t, "--release-limit", "1")
	require.NoError(t, err, output)
	assert.Equal(t, int64(2), externalRequests.Load())
	assert.Contains(t, output, `"scannedAssets":2`)
	assert.NotContains(t, output, "do-not-log")
}

func TestReleaseScanPortalFindingURL(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(fmt.Sprint(direct), func(t *testing.T) {
			assets := links("/asset?signature=do-not-log")
			portal := "https://gitlab.example.com/group/project/-/releases/version%2F1/downloads/asset"
			if direct {
				assets[0]["direct_asset_url"] = portal
			}
			f := newFixture(t, assets, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "do-not-log", r.URL.Query().Get("signature"))
				assert.Equal(t, "test-token", r.Header.Get("Private-Token"))
				assert.Empty(t, r.Header.Get("Authorization"))
				plainAsset(w, r)
			})
			output, err := f.run(t, "--repo", "group/project", "--tag", "version/1")
			require.NoError(t, err, output)
			if !direct {
				portal = f.server.URL + "/group/project/-/releases/version%2F1"
			}
			var found bool
			for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
				var event struct {
					Level string `json:"level"`
					URL   string `json:"url"`
				}
				require.NoError(t, json.Unmarshal([]byte(line), &event))
				if event.Level == "hit" {
					found = true
					assert.Equal(t, portal, event.URL)
				}
			}
			assert.True(t, found, "expected finding with portal URL")
			assert.NotContains(t, output, "do-not-log")
		})
	}
}

func TestReleaseScanPartialFailures(t *testing.T) {
	f := newFixture(t, links("/denied", "/good"), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/denied" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			plainAsset(w, r)
		}
	})
	output, err := f.run(t, "--release-limit", "1")
	require.Error(t, err)
	assert.Contains(t, output, "releasefixture")
	assert.Contains(t, output, `"failures":1`)
	assert.Contains(t, output, `"scannedAssets":1`)
	assert.Contains(t, output, "incomplete")
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var event struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		if event.Message == "Failed scanning release asset" {
			assert.Equal(t, "error", event.Level)
		}
	}
}

func TestReleaseScanSizeAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		fail bool
		want string
	}{
		{"size", []string{"--max-artifact-size", "1B"}, false, `"skippedAssets":1`},
		{"timeout", []string{"--hit-timeout", "1ns"}, true, "timed out"},
		{"confidence", []string{"--confidence", "low"}, false, `"scannedAssets":1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, links("/asset"), plainAsset)
			args := append([]string{"--release-limit", "1"}, tc.args...)
			output, err := f.run(t, args...)
			if tc.fail {
				require.Error(t, err, output)
			} else {
				require.NoError(t, err, output)
			}
			assert.Contains(t, output, tc.want)
			if tc.name == "timeout" {
				found := false
				for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
					var event struct {
						Level   string `json:"level"`
						Message string `json:"message"`
					}
					require.NoError(t, json.Unmarshal([]byte(line), &event))
					if event.Message == "Failed scanning release asset" {
						found = true
						assert.Equal(t, "warn", event.Level)
					}
				}
				assert.True(t, found, "expected asset timeout warning")
				assert.Contains(t, output, `"failures":1`)
			}
			if tc.name == "size" {
				assert.NotContains(t, output, `"level":"hit"`)
				assert.NotContains(t, output, "Skipped release asset exceeding maximum size")
			}

			if tc.name == "confidence" {
				assert.NotContains(t, output, `"confidence":"medium"`)
				assert.Contains(t, output, `"confidence":"low"`)
			}
		})
	}
}

func TestReleaseScanSizeSkipDebugLog(t *testing.T) {
	f := newFixture(t, links("/asset"), plainAsset)
	output, err := f.run(t, "--release-limit", "1", "--max-artifact-size", "1B", "--log-level", "debug")
	require.NoError(t, err, output)
	assert.Contains(t, output, `"level":"debug"`)
	assert.Contains(t, output, "Skipped release asset exceeding maximum size")
	assert.Contains(t, output, `"skippedAssets":1`)
}

func TestReleaseScanProjectURLDebugLog(t *testing.T) {
	f := newFixture(t, links("/asset"), plainAsset)
	for _, level := range []string{"info", "debug"} {
		t.Run(level, func(t *testing.T) {
			output, err := f.run(t, "--release-limit", "1", "--log-level", level)
			require.NoError(t, err, output)
			var found bool
			for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
				var event struct {
					Level   string `json:"level"`
					Message string `json:"message"`
					URL     string `json:"url"`
				}
				require.NoError(t, json.Unmarshal([]byte(line), &event))
				if event.Message == "Fetch project releases" {
					found = true
					assert.Equal(t, "debug", event.Level)
					assert.Equal(t, f.server.URL+"/group/project", event.URL)
				}
			}
			assert.Equal(t, level == "debug", found)
		})
	}
}

func TestReleaseScanUnavailableAssetsAreSilent(t *testing.T) {
	f := newFixture(t, links("/forbidden", "/missing", "/good"), func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		default:
			plainAsset(w, r)
		}
	})
	output, err := f.run(t, "--release-limit", "1")
	require.NoError(t, err, output)
	assert.NotContains(t, output, "Failed scanning release asset")
	assert.NotContains(t, output, `"level":"error"`)
	assert.NotContains(t, output, `"level":"warn"`)
	assert.Contains(t, output, `"skippedAssets":2`)
	assert.Contains(t, output, `"scannedAssets":1`)
	assert.Contains(t, output, `"failures":0`)
}

func TestReleaseScanForbiddenListingIsIgnored(t *testing.T) {
	testutil.UseTestRules(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			_, _ = fmt.Fprint(w, `[{"id":1,"path_with_namespace":"group/forbidden"}]`)
		case "/api/v4/projects/1/releases":
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"message":"403 Forbidden"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	output, err := (fixture{server: srv}).run(t)
	require.NoError(t, err, output)
	assert.NotContains(t, output, "Failed discovering release assets")
	assert.NotContains(t, output, `"level":"error"`)
	assert.Contains(t, output, `"failures":0`)
}

func TestReleaseScanWorkerBound(t *testing.T) {
	var active, peak atomic.Int64
	f := newFixture(t, links("/one", "/two", "/three", "/four", "/five"), func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(40 * time.Millisecond)
		active.Add(-1)
		plainAsset(w, r)
	})
	output, err := f.run(t, "--release-limit", "1", "--threads", "2")
	require.NoError(t, err, output)
	assert.Equal(t, int64(2), peak.Load())
	assert.Contains(t, output, `"scannedAssets":5`)
}

func TestReleaseScanVerificationDisabled(t *testing.T) {
	f := newFixture(t, links("/asset"), func(w http.ResponseWriter, r *http.Request) {
		assert.NotEqual(t, "/api/v4/user", r.URL.Path)
		_, _ = fmt.Fprint(w, "glpat-abcdefghijklmnopqrst")
	})
	output, err := f.run(t, "--release-limit", "1", "--secrets-verification=false")
	require.NoError(t, err, output)
	assert.Contains(t, output, `"ruleName":"Gitlab - Personal Access Token v2"`)
	assert.Contains(t, output, `"confidence":"high"`)
	for _, req := range f.requests() {
		assert.NotEqual(t, "/api/v4/user", req.Path)
	}
}

func TestReleaseScanInvalidConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"--tag", "v1"}, {"--release-limit", "-1"}, {"--threads", "0"}, {"--max-artifact-size", "0B"},
		{"--hit-timeout", "0s"}, {"--repo", "group/project", "--namespace", "group"},
		{"--repo", "group/project", "--tag", "v1", "--release-limit", "1"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			f := newFixture(t, nil, plainAsset)
			output, err := f.run(t, args...)
			require.Error(t, err)
			assert.Contains(t, output, "Invalid release scan configuration")
			assert.Empty(t, f.requests())
		})
	}
}

func TestReleaseScanWebUI(t *testing.T) {
	binary := os.Getenv("PIPELEEK_BINARY")
	require.NotEmpty(t, binary, "e2e tests require PIPELEEK_BINARY")
	binary, err := filepath.Abs(binary)
	require.NoError(t, err)
	f := newFixture(t, links("/asset"), plainAsset)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "gl", "release", "scan",
		"--url", f.server.URL, "--token", "test-token", "--release-limit", "1",
		"--secrets-verification=false", "--webui", "--json")
	cmd.Env = append(os.Environ(), "PIPELEEK_NO_CONFIG=1")
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	lines := bufio.NewScanner(stdout)
	var uiURL string
	var finished bool
	for lines.Scan() {
		var event struct {
			Message string `json:"message"`
			URL     string `json:"url"`
		}
		require.NoError(t, json.Unmarshal(lines.Bytes(), &event))
		if event.Message == "Findings web UI started" {
			uiURL = event.URL
		}
		if event.Message == "Release scan finished" {
			finished = true
			break
		}
	}
	require.NoError(t, lines.Err())
	require.True(t, finished, stderr.String())
	require.NotEmpty(t, uiURL)
	u, err := url.Parse(uiURL)
	require.NoError(t, err)
	u.Path = "/events"
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(u.String())
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var body strings.Builder
	events := bufio.NewScanner(response.Body)
	for events.Scan() {
		body.WriteString(events.Text())
		body.WriteByte('\n')
		if events.Text() == "event: done" {
			break
		}
	}
	require.NoError(t, events.Err())
	assert.Contains(t, body.String(), "releasefixture")
	assert.Contains(t, body.String(), `"project":"group/project"`)
	assert.Contains(t, body.String(), `"tag":"v2"`)
	assert.Contains(t, body.String(), "event: done")
}
