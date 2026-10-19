package detectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabSharedPATFormats(t *testing.T) {
	detector := NewGitLabURLDetector()
	for _, test := range []struct {
		name, token, wantName string
	}{
		{"v2", "glpat-" + strings.Repeat("a", 20), "Gitlab - Personal Access Token v2"},
		{"v3", "glpat-" + strings.Repeat("a", 27) + ".ab.123456789", "Gitlab - Personal Access Token v3"},
		{"oversized v2", "glpat-" + strings.Repeat("a", 23), ""},
		{"malformed v3", "glpat-" + strings.Repeat("a", 27) + "XabX123456789", ""},
		{"embedded prefix", "prefixglpat-" + strings.Repeat("a", 20), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			results, err := detector.FromDataWithURL(context.Background(), false, []byte("TOKEN="+test.token+","), "")
			require.NoError(t, err)
			if test.wantName == "" {
				assert.Empty(t, results)
				return
			}

			require.Len(t, results, 1)
			assert.Equal(t, test.wantName, results[0].DetectorName)
			assert.Equal(t, test.token, string(results[0].Raw))
			assert.False(t, results[0].Verified)
		})
	}
}

func TestGitLabColoredTokens(t *testing.T) {
	token := "glpat-" + strings.Repeat("a", 20)
	detector := NewGitLabURLDetector()
	for _, data := range []string{
		"\x1b[32m" + token + "\x1b[0m",
		"TOKEN=\x1b[32m" + token + "\x1b[0m",
		"\x1b[32m" + token + "\x1b[0m " + token,
	} {
		results, err := detector.FromDataWithURL(context.Background(), false, []byte(data), "")
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, token, string(results[0].Raw))
	}
}

func TestGitLabColoredTokenVerification(t *testing.T) {
	token := "glpat-" + strings.Repeat("a", 20)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "/api/v4/user", r.URL.Path)
		assert.Equal(t, token, r.Header.Get("Private-Token"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer server.Close()
	results, err := NewGitLabURLDetector().FromDataWithURL(
		context.Background(), true, []byte("\x1b[32m"+token+"\x1b[0m"), server.URL,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Verified)
	assert.Equal(t, token, string(results[0].Raw))
	assert.Equal(t, int32(1), requests.Load())
}
