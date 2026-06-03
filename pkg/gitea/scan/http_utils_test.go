package gitea

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"code.gitea.io/sdk/gitea"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"resty.dev/v3"
)

func TestBuildGiteaURL(t *testing.T) {
	tests := []struct {
		name        string
		giteaURL    string
		pathFormat  string
		args        []interface{}
		expected    string
		expectError bool
	}{
		{
			name:        "simple path",
			giteaURL:    "https://gitea.example.com",
			pathFormat:  "/issues",
			args:        nil,
			expected:    "https://gitea.example.com/issues",
			expectError: false,
		},
		{
			name:        "path with format args",
			giteaURL:    "https://gitea.example.com",
			pathFormat:  "/%s/actions/runs/%d",
			args:        []interface{}{"owner/repo", 123},
			expected:    "https://gitea.example.com/owner/repo/actions/runs/123",
			expectError: false,
		},
		{
			name:        "invalid URL",
			giteaURL:    "://invalid-url",
			pathFormat:  "/test",
			args:        nil,
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanOptions.GiteaURL = tt.giteaURL

			result, err := buildGiteaURL(tt.pathFormat, tt.args...)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestBuildAPIURL(t *testing.T) {
	tests := []struct {
		name        string
		giteaURL    string
		repo        *gitea.Repository
		pathFormat  string
		pathArgs    []interface{}
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:     "valid API URL",
			giteaURL: "https://gitea.example.com",
			repo: &gitea.Repository{
				Name: "test-repo",
				Owner: &gitea.User{
					UserName: "test-owner",
				},
			},
			pathFormat:  "/actions/runs/%d",
			pathArgs:    []interface{}{123},
			expected:    "https://gitea.example.com/api/v1/repos/test-owner/test-repo/actions/runs/123",
			expectError: false,
		},
		{
			name:        "nil repository",
			giteaURL:    "https://gitea.example.com",
			repo:        nil,
			pathFormat:  "/actions/runs/%d",
			pathArgs:    []interface{}{123},
			expected:    "",
			expectError: true,
			errorMsg:    "repository is nil",
		},
		{
			name:     "nil repository owner",
			giteaURL: "https://gitea.example.com",
			repo: &gitea.Repository{
				Name:  "test-repo",
				Owner: nil,
			},
			pathFormat:  "/actions/runs/%d",
			pathArgs:    []interface{}{123},
			expected:    "",
			expectError: true,
			errorMsg:    "repository owner is nil",
		},
		{
			name:     "invalid Gitea URL",
			giteaURL: "://invalid",
			repo: &gitea.Repository{
				Name: "test-repo",
				Owner: &gitea.User{
					UserName: "test-owner",
				},
			},
			pathFormat:  "/actions/runs/%d",
			pathArgs:    []interface{}{123},
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanOptions.GiteaURL = tt.giteaURL

			result, err := buildAPIURL(tt.repo, tt.pathFormat, tt.pathArgs...)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCheckHTTPStatus(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		operation   string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "success 200",
			statusCode:  200,
			operation:   "fetch data",
			expectError: false,
		},
		{
			name:        "not found 404",
			statusCode:  404,
			operation:   "fetch data",
			expectError: true,
			errorMsg:    "resource not found (404)",
		},
		{
			name:        "forbidden 403",
			statusCode:  403,
			operation:   "fetch data",
			expectError: true,
			errorMsg:    "access forbidden (403)",
		},
		{
			name:        "gone 410",
			statusCode:  410,
			operation:   "fetch data",
			expectError: true,
			errorMsg:    "resource gone (410)",
		},
		{
			name:        "server error 500",
			statusCode:  500,
			operation:   "fetch data",
			expectError: true,
			errorMsg:    "HTTP error: 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkHTTPStatus(tt.statusCode, tt.operation)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMakeHTTPGetRequest(t *testing.T) {
	tests := []struct {
		name           string
		setupServer    func() *httptest.Server
		expectedStatus int
		expectedBody   string
		expectError    bool
		errorMsg       string
	}{
		{
			name: "successful GET request",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, http.MethodGet, r.Method)
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("test response"))
				}))
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "test response",
			expectError:    false,
		},
		{
			name: "404 response",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte("not found"))
				}))
			},
			expectedStatus: http.StatusNotFound,
			expectedBody:   "not found",
			expectError:    false,
		},
		{
			name: "server error",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte("server error"))
				}))
			},
			expectError:    false,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

scanOptions.HttpClient = resty.New().SetRetryCount(0)

			resp, err := makeHTTPGetRequest(server.URL)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				if resp != nil {
					assert.Equal(t, tt.expectedStatus, resp.StatusCode)
					assert.Equal(t, tt.expectedBody, string(resp.Body))
				}
			}
		})
	}
}

func TestMakeHTTPGetRequest_NilClient(t *testing.T) {
	scanOptions.HttpClient = nil

	resp, err := makeHTTPGetRequest("http://example.com")

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "HTTP client is not initialized")
}

func TestMakeHTTPPostRequest(t *testing.T) {
	tests := []struct {
		name           string
		setupServer    func() *httptest.Server
		requestBody    []byte
		headers        map[string]string
		expectedStatus int
		expectedBody   string
		expectError    bool
	}{
		{
			name: "successful POST request with headers",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, http.MethodPost, r.Method)
					assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
					assert.Equal(t, "test-token", r.Header.Get("x-csrf-token"))
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"status":"success"}`))
				}))
			},
			requestBody: []byte(`{"test":"data"}`),
			headers: map[string]string{
				"Content-Type": "application/json",
				"x-csrf-token": "test-token",
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"success"}`,
			expectError:    false,
		},
		{
			name: "POST with nil body",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("ok"))
				}))
			},
			requestBody:    nil,
			headers:        map[string]string{},
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

scanOptions.HttpClient = resty.New().SetRetryCount(0)

			resp, err := makeHTTPPostRequest(server.URL, tt.requestBody, tt.headers)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, resp.StatusCode)
				assert.Equal(t, tt.expectedBody, string(resp.Body))
			}
		})
	}
}

func TestMakeHTTPPostRequest_NilClient(t *testing.T) {
	scanOptions.HttpClient = nil

	resp, err := makeHTTPPostRequest("http://example.com", []byte("test"), nil)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "HTTP client is not initialized")
}

func TestLogHTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		operation  string
		ctx        logContext
	}{
		{
			name:       "error with full context",
			statusCode: 404,
			operation:  "download logs",
			ctx: logContext{
				Repo:  "owner/repo",
				RunID: 123,
				JobID: 456,
			},
		},
		{
			name:       "error with partial context",
			statusCode: 403,
			operation:  "fetch data",
			ctx: logContext{
				Repo: "owner/repo",
			},
		},
		{
			name:       "error with no context",
			statusCode: 500,
			operation:  "process request",
			ctx:        logContext{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output for verification
			var buf bytes.Buffer
			oldLogger := log.Logger
			log.Logger = zerolog.New(&buf).With().Timestamp().Logger()
			defer func() { log.Logger = oldLogger }()

			assert.NotPanics(t, func() {
				logHTTPError(tt.statusCode, tt.operation, tt.ctx)
			})

			output := buf.String()
			assert.Contains(t, output, tt.operation, "Log should contain operation name")

			assert.NotEmpty(t, output, "Should have logged error information")
		})
	}
}

func TestAuthTransport_RoundTrip(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		expectedAuth  string
		serverHandler http.HandlerFunc
		expectError   bool
	}{
		{
			name:         "adds authorization header",
			token:        "test-token-123",
			expectedAuth: "token test-token-123",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				assert.Equal(t, "token test-token-123", auth)
				w.WriteHeader(http.StatusOK)
			},
			expectError: false,
		},
		{
			name:         "empty token",
			token:        "",
			expectedAuth: "token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				// When token is empty, we get "token " but HTTP may trim trailing space
				assert.Contains(t, auth, "token")
				w.WriteHeader(http.StatusOK)
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			transport := &AuthTransport{
				Base:  http.DefaultTransport,
				Token: tt.token,
			}

			client := &http.Client{Transport: transport}

			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			assert.NoError(t, err)

			resp, err := client.Do(req)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				_ = resp.Body.Close()
			}
		})
	}
}

// Test setup helper
func setupTestScanOptions() {
	scanOptions = GiteaScanOptions{
		Token:                  "test-token",
		GiteaURL:               "https://gitea.example.com",
		Artifacts:              false,
		ConfidenceFilter:       []string{},
		MaxScanGoRoutines:      4,
		TruffleHogVerification: false,
		Owned:                  false,
		Organization:           "",
		Repository:             "",
		Cookie:                 "",
		RunsLimit:              0,
		StartRunID:             0,
		Context:                context.Background(),
		Client:                 nil,
		HttpClient:             resty.New().SetRetryCount(0),
	}
}

func TestMain(m *testing.M) {
	// Setup before tests
	setupTestScanOptions()

	// Run tests
	m.Run()
}

func TestMakeHTTPPostRequest_WithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		body, _ := io.ReadAll(r.Body)
		assert.Equal(t, "test body", string(body))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	setupTestScanOptions()

	headers := map[string]string{
		"Content-Type": "application/json",
	}
	body := []byte("test body")

	resp, err := makeHTTPPostRequest(server.URL, body, headers)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	if resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

func TestMakeHTTPGetRequest_WithQueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "value", r.URL.Query().Get("param"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	setupTestScanOptions()

	resp, err := makeHTTPGetRequest(server.URL + "?param=value")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	if resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

func TestCheckHTTPStatus_410Gone(t *testing.T) {
	err := checkHTTPStatus(http.StatusGone, "test operation")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "410")
}
