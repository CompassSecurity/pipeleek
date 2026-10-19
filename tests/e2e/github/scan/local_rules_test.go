package e2e

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubScan_LocalRulesAndLevels(t *testing.T) {
	require.True(t, filepath.IsAbs(os.Getenv("PIPELEEK_BINARY")), "Use an absolute PIPELEEK_BINARY for isolated working-directory tests")
	dir := t.TempDir()
	t.Chdir(dir)
	archive := func(name, content string) []byte {
		var buffer bytes.Buffer
		writer := zip.NewWriter(&buffer)
		file, err := writer.Create(name)
		require.NoError(t, err)
		_, err = file.Write([]byte(content))
		require.NoError(t, err)
		require.NoError(t, writer.Close())
		return buffer.Bytes()
	}
	logs := archive("job.log", "GITLAB_USER_ID=19357\nGITLAB_TOKEN=glpat-abcdefghijklmnopqrst\nPIPELEEK_LOG_FIXTURE\n")
	artifact := archive("settings.txt", "KUBECONFIG=/tmp/local-config\nPIPELEEK_ARTIFACT_FIXTURE\n")
	server, requests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/user/repos":
			testutil.JSON(w, http.StatusOK, []map[string]interface{}{{
				"id": 1, "name": "test-repo", "full_name": "user/test-repo",
				"html_url": "https://example.test/user/test-repo",
				"owner":    map[string]interface{}{"login": "user"},
			}})
		case "/api/v3/repos/user/test-repo/actions/runs":
			testutil.JSON(w, http.StatusOK, map[string]interface{}{
				"total_count": 1,
				"workflow_runs": []map[string]interface{}{{
					"id": 100, "name": "Local rules", "status": "completed", "display_title": "Local rules",
					"html_url":   "https://example.test/runs/100",
					"repository": map[string]interface{}{"name": "test-repo", "owner": map[string]interface{}{"login": "user"}},
				}},
			})
		case "/api/v3/repos/user/test-repo/actions/runs/100/jobs":
			testutil.JSON(w, http.StatusOK, map[string]interface{}{"jobs": []map[string]interface{}{{"id": 1000, "name": "fixture-job"}}, "total_count": 1})
		case "/api/v3/repos/user/test-repo/actions/runs/100/logs":
			w.Header().Set("Location", "http://"+r.Host+"/download/logs.zip")
			w.WriteHeader(http.StatusFound)
		case "/download/logs.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(logs)
		case "/api/v3/repos/user/test-repo/actions/runs/100/artifacts":
			testutil.JSON(w, http.StatusOK, map[string]interface{}{
				"artifacts": []map[string]interface{}{{
					"id": 1, "name": "fixture-output",
					"archive_download_url": "http://" + r.Host + "/api/v3/repos/user/test-repo/actions/artifacts/1/zip",
				}}, "total_count": 1,
			})
		case "/api/v3/repos/user/test-repo/actions/artifacts/1/zip":
			w.Header().Set("Location", "http://"+r.Host+"/download/artifact.zip")
			w.WriteHeader(http.StatusFound)
		case "/download/artifact.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(artifact)
		default:
			testutil.JSON(w, http.StatusOK, map[string]interface{}{})
		}
	})
	defer cleanup()

	run := func(confidence string) []map[string]interface{} {
		t.Helper()
		args := []string{"gh", "scan", "--url", server.URL, "--token", "fixture-token", "--owned", "--artifacts", "--secrets-verification=false", "--json", "--verbose"}
		if confidence != "" {
			args = append(args, "--confidence="+confidence)
		}
		stdout, stderr, err := testutil.RunCLI(t, args, nil, time.Minute)
		require.NoError(t, err, stdout+stderr)
		var findings []map[string]interface{}
		for _, line := range strings.Split(stdout+"\n"+stderr, "\n") {
			var record map[string]interface{}
			if json.Unmarshal([]byte(line), &record) == nil && record["message"] == "SECRET" {
				findings = append(findings, record)
			}
		}
		return findings
	}
	has := func(findings []map[string]interface{}, confidence, value string) bool {
		for _, finding := range findings {
			text, ok := finding["value"].(string)
			if ok && finding["confidence"] == confidence && strings.Contains(text, value) {
				return true
			}
		}
		return false
	}
	findings := run("")
	assert.True(t, has(findings, "medium", "GITLAB_USER_ID=19357"), "Retain the identifier rule without a local rules file")
	assert.True(t, has(findings, "medium", "KUBECONFIG=/tmp/local-config"), "Retain path matching in artifacts")
	assert.True(t, has(findings, "trufflehog", "glpat-abcdefghijklmnopqrst"), "Offline TruffleHog candidates use the new level")
	_, err := os.Stat(filepath.Join(dir, "rules.yml"))
	assert.True(t, os.IsNotExist(err), "Scanning must not create or download rules")
	assert.Empty(t, run("verified"), "Offline fixtures must not become verified")
	candidates := run("trufflehog")
	require.NotEmpty(t, candidates)
	for _, finding := range candidates {
		assert.Equal(t, "trufflehog", finding["confidence"])
		assert.Equal(t, "trufflehog", finding["engine"])
	}

	custom := []byte(`patterns:
  - pattern:
      name: Gitlab - Predefined Environment Variable
      regex: PIPELEEK_(LOG|ARTIFACT)_FIXTURE
      confidence: custom-confidence
`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.yml"), custom, 0600))
	findings = run("custom-confidence,medium")
	assert.True(t, has(findings, "custom-confidence", "PIPELEEK_LOG_FIXTURE"))
	assert.True(t, has(findings, "custom-confidence", "PIPELEEK_ARTIFACT_FIXTURE"))
	for _, finding := range findings {
		assert.Equal(t, "custom-confidence", finding["confidence"], "The overridden variable rule must not emit medium findings")
	}
	unchanged, err := os.ReadFile(filepath.Join(dir, "rules.yml"))
	require.NoError(t, err)
	assert.Equal(t, custom, unchanged)
	assert.NotEmpty(t, requests())

	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.yml"), []byte("patterns:\n- pattern: {name: InvalidFixture, regex: '[', confidence: high}\n"), 0600))
	stdout, stderr, err := testutil.RunCLI(t, []string{"gh", "scan", "--url", server.URL, "--token", "fixture-token", "--secrets-verification=false"}, nil, time.Minute)
	require.Error(t, err)
	assert.Contains(t, stdout+stderr, "InvalidFixture")
	assert.Contains(t, stdout+stderr, "invalid regex")
	assert.Contains(t, stdout+stderr, "Failed loading rules")
}
