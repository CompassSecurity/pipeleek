package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const downloadFixture = "patterns:\n  - pattern:\n      name: Fixture\n      regex: FIXTURE_[A-Z]+\n      confidence: high\n"

func TestDownload(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		status    int
		existing  bool
		force     bool
		wantError bool
	}{
		{name: "success", body: downloadFixture, status: 200},
		{name: "existing", body: downloadFixture, status: 200, existing: true, wantError: true},
		{name: "force", body: downloadFixture, status: 200, existing: true, force: true},
		{name: "http error", status: 404, wantError: true},
		{name: "http error preserves existing", status: 404, existing: true, force: true, wantError: true},
		{name: "yaml error", body: "[", status: 200, wantError: true},
		{name: "empty", body: "patterns: []", status: 200, wantError: true},
		{name: "oversized", body: strings.Repeat(" ", (16<<20)+1), status: 200, wantError: true},
		{name: "invalid regex", body: "patterns: [{pattern: {name: test, regex: '[', confidence: high}}]", status: 200, existing: true, force: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			dir := t.TempDir()
			output := filepath.Join(dir, "rules.yml")
			if tc.existing {
				require.NoError(t, os.WriteFile(output, []byte("original"), 0600))
			}

			count, err := download(context.Background(), server.Client(), server.URL, output, tc.force)
			if tc.wantError {
				require.Error(t, err)
				if tc.existing {
					data, err := os.ReadFile(output)
					require.NoError(t, err)
					require.Equal(t, "original", string(data))
				} else {
					_, err := os.Stat(output)
					require.True(t, os.IsNotExist(err))
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, count)
				data, err := os.ReadFile(output)
				require.NoError(t, err)
				require.Equal(t, tc.body, string(data))
			}
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			for _, entry := range entries {
				require.Equal(t, "rules.yml", entry.Name(), "No temporary files should remain")
			}
		})
	}
}

func TestDownloadCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	output := filepath.Join(t.TempDir(), "rules.yml")
	_, err := download(ctx, http.DefaultClient, ExternalRulesURL, output, false)
	require.ErrorIs(t, err, context.Canceled)
	_, err = os.Stat(output)
	require.True(t, os.IsNotExist(err))
}

func TestDownloadDoesNotOverwriteConcurrentFile(t *testing.T) {
	output := filepath.Join(t.TempDir(), "rules.yml")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, os.WriteFile(output, []byte("concurrent"), 0600))
		_, _ = w.Write([]byte(downloadFixture))
	}))
	defer server.Close()
	_, err := download(context.Background(), server.Client(), server.URL, output, false)
	require.Error(t, err)
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "concurrent", string(data))
}
