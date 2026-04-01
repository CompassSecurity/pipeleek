package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestJenkinsScan_HappyPath(t *testing.T) {
	server, getRequests, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		baseURL := "http://" + r.Host

		switch {
		case r.URL.Path == "/api/json":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jobs": []map[string]interface{}{
					{
						"_class": "hudson.model.FreeStyleProject",
						"name":   "demo",
						"url":    baseURL + "/job/demo/",
					},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/job/demo/api/json") && strings.Contains(r.URL.RawQuery, "allBuilds"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"allBuilds": []map[string]interface{}{{
					"number": 1,
					"url":    baseURL + "/job/demo/1/",
				}},
			})
		case r.URL.Path == "/job/demo/api/json":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"name":     "demo",
				"fullName": "demo",
				"url":      baseURL + "/job/demo/",
			})
		case strings.HasPrefix(r.URL.Path, "/job/demo/1/api/json"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"number": 1,
				"url":    baseURL + "/job/demo/1/",
			})
		case r.URL.Path == "/job/demo/config.xml" || r.URL.Path == "/job/demo/config.xml/":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte("<project><description>demo</description></project>"))
		case r.URL.Path == "/job/demo/1/consoleText" || r.URL.Path == "/job/demo/1/consoleText/":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Build output\n"))
		case r.URL.Path == "/job/demo/1/injectedEnvVars/api/json":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"envMap": map[string]string{"FOO": "bar"},
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		}
	})
	defer cleanup()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{
		"jenkins", "scan",
		"--jenkins", server.URL,
		"--username", "admin",
		"--token", "apitoken",
		"--max-builds", "1",
	}, nil, 15*time.Second)

	assert.Nil(t, exitErr, "jenkins scan should succeed")
	requests := getRequests()
	assert.True(t, len(requests) >= 4, "should make multiple Jenkins API requests")

	sawBasicAuth := false
	for _, req := range requests {
		authHeader := req.Headers.Get("Authorization")
		if authHeader != "" {
			assert.True(t, strings.HasPrefix(authHeader, "Basic "), "expected basic auth header")
			sawBasicAuth = true
		}
	}
	assert.True(t, sawBasicAuth, "expected at least one request with basic auth header")

	t.Logf("STDOUT:\n%s", stdout)
	t.Logf("STDERR:\n%s", stderr)
}
