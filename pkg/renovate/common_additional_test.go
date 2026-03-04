package renovate

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeRenovateConfig_ValidJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain JSON",
			input:    `{"key": "value", "num": 42}`,
			expected: `{"key":"value","num":42}`,
		},
		{
			name:     "JSON with whitespace",
			input:    "{\n  \"extends\": [\n    \"config:base\"\n  ]\n}",
			expected: `{"extends":["config:base"]}`,
		},
		{
			name:     "empty object",
			input:    `{}`,
			expected: `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeRenovateConfig(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeRenovateConfig_JSON5(t *testing.T) {
	// JSON5 with trailing commas should be normalized
	input := `{
		"extends": ["config:base"],
		"prConcurrentLimit": 0,
	}`
	result := normalizeRenovateConfig(input)
	// Should be valid JSON (no trailing commas)
	assert.Contains(t, result, `"extends"`)
	assert.Contains(t, result, `"prConcurrentLimit"`)
}

func TestNormalizeRenovateConfig_InvalidInput(t *testing.T) {
	// Completely invalid input should be returned unchanged
	invalid := `this is not json at all !!!`
	result := normalizeRenovateConfig(invalid)
	assert.Equal(t, invalid, result)
}

func TestTryParseJSON_StringValue(t *testing.T) {
	val, ok := tryParseJSON(`{"key": "value"}`, "key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

func TestTryParseJSON_ArrayValue(t *testing.T) {
	val, ok := tryParseJSON(`{"items": ["a","b","c"]}`, "items")
	assert.True(t, ok)
	assert.Equal(t, `["a","b","c"]`, val)
}

func TestTryParseJSON_ObjectValue(t *testing.T) {
	val, ok := tryParseJSON(`{"nested": {"x": 1}}`, "nested")
	assert.True(t, ok)
	assert.Contains(t, val, `"x"`)
}

func TestTryParseJSON_NumberValue(t *testing.T) {
	val, ok := tryParseJSON(`{"count": 42}`, "count")
	assert.True(t, ok)
	assert.Equal(t, "42", val)
}

func TestTryParseJSON_MissingKey(t *testing.T) {
	_, ok := tryParseJSON(`{"other": "value"}`, "missing")
	assert.False(t, ok)
}

func TestTryParseJSON_InvalidJSON(t *testing.T) {
	_, ok := tryParseJSON(`not json`, "key")
	assert.False(t, ok)
}

func TestFetchCurrentSelfHostedOptions_Cached(t *testing.T) {
	// When cache is non-empty, it should be returned directly without HTTP call
	cached := []string{"option1", "option2", "option3"}
	// Use a real client - it should never be invoked since the cache returns early
	result := FetchCurrentSelfHostedOptions(cached, httpclient.GetPipeleekHTTPClient("", nil, nil))
	assert.Equal(t, cached, result)
}

func TestExtendRenovateConfig_ServiceUnavailable(t *testing.T) {
	// Use a mock server that returns 404 (not 5xx) to avoid triggering retries
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	originalConfig := `{"extends": ["config:base"]}`
	result := ExtendRenovateConfig(originalConfig, srv.URL, "owner/repo", httpclient.GetPipeleekHTTPClient("", nil, nil))
	// When service returns non-200, original config should be returned
	assert.Equal(t, originalConfig, result)
}

func TestExtendRenovateConfig_ServiceReturnsExtended(t *testing.T) {
	extendedConfig := `{"extends": ["config:base"], "extra": "added"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/resolve", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(extendedConfig))
	}))
	defer srv.Close()

	originalConfig := `{"extends": ["config:base"]}`
	result := ExtendRenovateConfig(originalConfig, srv.URL, "owner/repo", httpclient.GetPipeleekHTTPClient("", nil, nil))
	assert.Equal(t, extendedConfig, result)
}

func TestExtendRenovateConfig_ServiceReturnsError(t *testing.T) {
	// Use 400 (client error, non-retryable) to test non-200 fallback
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "bad request"}`))
	}))
	defer srv.Close()

	originalConfig := `{"extends": ["config:base"]}`
	result := ExtendRenovateConfig(originalConfig, srv.URL, "owner/repo", httpclient.GetPipeleekHTTPClient("", nil, nil))
	// On non-200, original config should be returned
	assert.Equal(t, originalConfig, result)
}

func TestExtendRenovateConfig_InvalidServiceURL(t *testing.T) {
	originalConfig := `{"extends": ["config:base"]}`
	result := ExtendRenovateConfig(originalConfig, "://invalid-url", "owner/repo", httpclient.GetPipeleekHTTPClient("", nil, nil))
	assert.Equal(t, originalConfig, result)
}

func TestValidateRenovateConfigService_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	}))
	defer srv.Close()

	err := ValidateRenovateConfigService(srv.URL, httpclient.GetPipeleekHTTPClient("", nil, nil))
	assert.NoError(t, err)
}

func TestValidateRenovateConfigService_Unhealthy(t *testing.T) {
	// Use 404 (not 5xx) to avoid triggering the retry mechanism
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := ValidateRenovateConfigService(srv.URL, httpclient.GetPipeleekHTTPClient("", nil, nil))
	assert.Error(t, err)
}

func TestValidateRenovateConfigService_InvalidURL(t *testing.T) {
	err := ValidateRenovateConfigService("://bad-url", httpclient.GetPipeleekHTTPClient("", nil, nil))
	assert.Error(t, err)
}
