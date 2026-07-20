package whoami

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchWhoAmI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":42,"username":"alice","name":"Alice","email":"alice@example.com","is_admin":false,"bot":false}`))
	})
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":99,"name":"test-token","revoked":false,"created_at":"2025-01-01T00:00:00Z","description":"token desc","scopes":["api","read_api"],"user_id":42,"active":true,"expires_at":"2026-01-01","last_used_ips":["127.0.0.1"]}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	result, err := FetchWhoAmI(server.URL, "glpat-test")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	require.NotNil(t, result.Token)

	assert.Equal(t, "alice", result.User.Username)
	assert.Equal(t, "alice@example.com", result.User.Email)
	assert.Equal(t, "test-token", result.Token.Name)
	assert.Equal(t, []string{"api", "read_api"}, result.Token.Scopes)
}

func TestFetchWhoAmI_TokenRequestFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":42,"username":"alice","name":"Alice"}`))
	})
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	result, err := FetchWhoAmI(server.URL, "glpat-test")
	assert.Error(t, err)
	assert.Nil(t, result)
}
