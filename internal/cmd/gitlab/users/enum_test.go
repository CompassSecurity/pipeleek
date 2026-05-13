package users

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnumCommand_WithToken(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	config.ResetViper()
	t.Cleanup(config.ResetViper)

	var (
		mu       sync.Mutex
		requests []*http.Request
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Clone(r.Context()))
		mu.Unlock()

		require.Equal(t, "/api/v4/users", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer server.Close()

	cmd := NewEnumCmd()
	cmd.SetArgs([]string{"--gitlab", server.URL, "--token", "glpat-test"})

	require.NoError(t, cmd.Execute())

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, requests, 1)
	assert.Equal(t, "glpat-test", requests[0].Header.Get("PRIVATE-TOKEN"))
}

func TestEnumCommand_WithoutToken(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	config.ResetViper()
	t.Cleanup(config.ResetViper)

	var (
		mu       sync.Mutex
		requests []*http.Request
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Clone(r.Context()))
		mu.Unlock()

		require.Equal(t, "/api/v4/users", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer server.Close()

	cmd := NewEnumCmd()
	cmd.SetArgs([]string{"--gitlab", server.URL})

	require.NoError(t, cmd.Execute())

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, requests, 1)
	assert.Empty(t, requests[0].Header.Get("PRIVATE-TOKEN"))
}
