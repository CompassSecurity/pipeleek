package variables

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"code.gitea.io/sdk/gitea"
	"github.com/stretchr/testify/assert"
)

// handleVersionEndpoint handles the version endpoint for SDK initialization
func handleVersionEndpoint(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/api/v1/version" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "1.20.0"})
		return true
	}
	return false
}

func TestConfig(t *testing.T) {
	cfg := Config{
		URL:   "https://gitea.example.com",
		Token: "test-token",
	}

	if cfg.URL != "https://gitea.example.com" {
		t.Errorf("Expected URL to be https://gitea.example.com, got %s", cfg.URL)
	}

	if cfg.Token != "test-token" {
		t.Errorf("Expected Token to be test-token, got %s", cfg.Token)
	}
}

func TestListRepoActionVariables_Pagination(t *testing.T) {
	tests := []struct {
		name           string
		totalVariables int
		pageSize       int
		expectedPages  int
	}{
		{
			name:           "single page",
			totalVariables: 10,
			pageSize:       50,
			expectedPages:  1,
		},
		{
			name:           "exact page boundary",
			totalVariables: 50,
			pageSize:       50,
			expectedPages:  1,
		},
		{
			name:           "multiple pages",
			totalVariables: 125,
			pageSize:       50,
			expectedPages:  3,
		},
		{
			name:           "empty result",
			totalVariables: 0,
			pageSize:       50,
			expectedPages:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pageRequests := 0

			// Create mock server that simulates pagination
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if handleVersionEndpoint(w, r) {
					return
				}

				// Verify authorization header
				auth := r.Header.Get("Authorization")
				assert.Equal(t, "token test-token", auth)

				// Parse page and limit from query parameters
				pageStr := r.URL.Query().Get("page")
				limitStr := r.URL.Query().Get("limit")

				page, _ := strconv.Atoi(pageStr)
				limit, _ := strconv.Atoi(limitStr)

				if page == 0 {
					page = 1
				}
				if limit == 0 {
					limit = 50
				}

				pageRequests++

				// Calculate which variables to return for this page
				start := (page - 1) * limit
				end := start + limit
				if end > tt.totalVariables {
					end = tt.totalVariables
				}

				var variables []*gitea.RepoActionVariable
				for i := start; i < end; i++ {
					variables = append(variables, &gitea.RepoActionVariable{
						Name:  fmt.Sprintf("VAR_%d", i+1),
						Value: fmt.Sprintf("value_%d", i+1),
					})
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(variables)
			}))
			defer server.Close()

			// Create client context
			cfg := Config{
				URL:   server.URL,
				Token: "test-token",
			}
			ctx, err := createClientContext(cfg)
			assert.NoError(t, err)

			// Collect all variables across pages
			var allVariables []*gitea.RepoActionVariable
			page := 1
			for {
				variables, err := listRepoActionVariables(ctx, "owner", "repo", page, tt.pageSize)
				assert.NoError(t, err)

				if len(variables) == 0 {
					break
				}

				allVariables = append(allVariables, variables...)

				if len(variables) < tt.pageSize {
					break
				}
				page++
			}

			// Verify results
			assert.Equal(t, tt.totalVariables, len(allVariables), "Should fetch all variables")

			// Calculate expected pages - the code makes an extra request when results == pageSize
			// to check if there are more pages
			var expectedPages int
			if tt.totalVariables == 0 {
				expectedPages = 1 // At least one request for empty result
			} else if tt.totalVariables%tt.pageSize == 0 && tt.totalVariables > 0 {
				// When we get exactly pageSize results, we make one more request to check if there's more
				expectedPages = (tt.totalVariables / tt.pageSize) + 1
			} else {
				expectedPages = (tt.totalVariables / tt.pageSize) + 1
			}
			assert.Equal(t, expectedPages, pageRequests, "Should make expected number of page requests")

			// Verify variable names are correct
			for i, v := range allVariables {
				assert.Equal(t, fmt.Sprintf("VAR_%d", i+1), v.Name)
				assert.Equal(t, fmt.Sprintf("value_%d", i+1), v.Value)
			}
		})
	}
}

func TestListRepoActionVariables_ErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		expectError    bool
	}{
		{
			name: "successful response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				variables := []*gitea.RepoActionVariable{
					{Name: "VAR1", Value: "value1"},
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(variables)
			},
			expectError: false,
		},
		{
			name: "404 not found",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message": "Not Found"}`))
			},
			expectError: true,
		},
		{
			name: "401 unauthorized",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message": "Unauthorized"}`))
			},
			expectError: true,
		},
		{
			name: "server error",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotImplemented)
				_, _ = w.Write([]byte(`{"message": "Not Implemented"}`))
			},
			expectError: true,
		},
		{
			name: "invalid JSON response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{invalid json`))
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if handleVersionEndpoint(w, r) {
					return
				}
				tt.serverResponse(w, r)
			}))
			defer server.Close()

			cfg := Config{
				URL:   server.URL,
				Token: "test-token",
			}
			ctx, err := createClientContext(cfg)
			assert.NoError(t, err)

			_, err = listRepoActionVariables(ctx, "owner", "repo", 1, 50)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFetchRepoVariables_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handleVersionEndpoint(w, r) {
			return
		}

		pageStr := r.URL.Query().Get("page")
		page, _ := strconv.Atoi(pageStr)
		if page == 0 {
			page = 1
		}

		var variables []*gitea.RepoActionVariable

		// Page 1: 50 variables
		if page == 1 {
			for i := 0; i < 50; i++ {
				variables = append(variables, &gitea.RepoActionVariable{
					Name:  fmt.Sprintf("VAR_%d", i+1),
					Value: fmt.Sprintf("value_%d", i+1),
				})
			}
		}
		// Page 2: 25 variables
		if page == 2 {
			for i := 50; i < 75; i++ {
				variables = append(variables, &gitea.RepoActionVariable{
					Name:  fmt.Sprintf("VAR_%d", i+1),
					Value: fmt.Sprintf("value_%d", i+1),
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(variables)
	}))
	defer server.Close()

	cfg := Config{
		URL:   server.URL,
		Token: "test-token",
	}
	ctx, err := createClientContext(cfg)
	assert.NoError(t, err)

	// This should make 2 requests and stop when it gets < 50 results
	err = fetchRepoVariables(ctx, "owner", "repo")
	assert.NoError(t, err)
}
