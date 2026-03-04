package renovate

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/stretchr/testify/assert"
)

func TestDetectCiCdConfig(t *testing.T) {
	tests := []struct {
		name     string
		cicdConf string
		want     bool
	}{
		{
			name:     "detects renovate/renovate image",
			cicdConf: "image: renovate/renovate:latest",
			want:     true,
		},
		{
			name:     "detects renovatebot/renovate image",
			cicdConf: "image: renovatebot/renovate:37",
			want:     true,
		},
		{
			name:     "detects renovate-bot/renovate-runner",
			cicdConf: "uses: renovate-bot/renovate-runner@v1",
			want:     true,
		},
		{
			name:     "detects RENOVATE_ environment variables",
			cicdConf: "RENOVATE_TOKEN: ${{ secrets.TOKEN }}",
			want:     true,
		},
		{
			name:     "detects npx renovate command",
			cicdConf: "run: npx renovate --help",
			want:     true,
		},
		{
			name:     "case insensitive detection",
			cicdConf: "IMAGE: RENOVATE/RENOVATE:LATEST",
			want:     true,
		},
		{
			name:     "no renovate configuration",
			cicdConf: "image: node:18\nrun: npm test",
			want:     false,
		},
		{
			name:     "empty configuration",
			cicdConf: "",
			want:     false,
		},
		{
			name: "detects renovatebot/github-action",
			cicdConf: `jobs:
  renovate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v6.0.1
      - name: Self-hosted Renovate
        uses: renovatebot/github-action@v44.2.2
        with:
          docker-cmd-file: .github/renovate-entrypoint.sh
          docker-user: root
          token: ${{ secrets.RENOVATE_TOKEN }}`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectCiCdConfig(tt.cicdConf)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDetectAutodiscovery(t *testing.T) {
	tests := []struct {
		name              string
		cicdConf          string
		configFileContent string
		want              bool
	}{
		{
			name:              "detects autodiscover in config file",
			cicdConf:          "",
			configFileContent: `{"autodiscover": true}`,
			want:              true,
		},
		{
			name:              "detects --autodiscover flag in CI/CD",
			cicdConf:          "renovate --autodiscover",
			configFileContent: "",
			want:              true,
		},
		{
			name:              "detects RENOVATE_AUTODISCOVER env var",
			cicdConf:          "RENOVATE_AUTODISCOVER: true",
			configFileContent: "",
			want:              true,
		},
		{
			name:              "ignores --autodiscover=false",
			cicdConf:          "renovate --autodiscover=false",
			configFileContent: "",
			want:              false,
		},
		{
			name:              "ignores --autodiscover false",
			cicdConf:          "renovate --autodiscover false",
			configFileContent: "",
			want:              false,
		},
		{
			name:              "ignores RENOVATE_AUTODISCOVER: false",
			cicdConf:          "RENOVATE_AUTODISCOVER: false",
			configFileContent: "",
			want:              false,
		},
		{
			name:              "ignores RENOVATE_AUTODISCOVER=false",
			cicdConf:          "RENOVATE_AUTODISCOVER=false",
			configFileContent: "",
			want:              false,
		},
		{
			name:              "no autodiscovery configuration",
			cicdConf:          "renovate --help",
			configFileContent: `{"extends": ["config:base"]}`,
			want:              false,
		},
		{
			name:              "case insensitive detection",
			cicdConf:          "RENOVATE --AUTODISCOVER",
			configFileContent: "",
			want:              true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectAutodiscovery(tt.cicdConf, tt.configFileContent)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDetectAutodiscoveryFilters(t *testing.T) {
	tests := []struct {
		name              string
		cicdConf          string
		configFileContent string
		wantHasFilters    bool
		wantFilterType    string
		wantFilterValue   string
	}{
		{
			name:              "detects autodiscoverFilter with GitHub Actions template",
			cicdConf:          "RENOVATE_AUTODISCOVER_FILTER: ${{ github.repository }}",
			configFileContent: "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverFilter",
			wantFilterValue:   "${{ github.repository }}",
		},
		{
			name:              "detects autodiscoverFilter with complex GitHub Actions expression",
			cicdConf:          "RENOVATE_AUTODISCOVER_FILTER: /${{ github.repository_owner }}/.*/",
			configFileContent: "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverFilter",
			wantFilterValue:   "/${{ github.repository_owner }}/.*/",
		},
		{
			name:              "detects autodiscoverFilter in config file",
			configFileContent: `{"autodiscoverFilter": "owner/repo"}`,
			cicdConf:          "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverFilter",
			wantFilterValue:   "owner/repo",
		},
		{
			name:              "detects autodiscoverNamespaces",
			cicdConf:          "RENOVATE_AUTODISCOVER_NAMESPACES: my-namespace",
			configFileContent: "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverNamespaces",
			wantFilterValue:   "my-namespace",
		},
		{
			name:              "detects autodiscoverProjects",
			cicdConf:          "--autodiscover-projects owner/repo",
			configFileContent: "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverProjects",
			wantFilterValue:   "owner/repo",
		},
		{
			name:              "detects autodiscoverTopics",
			configFileContent: `{"autodiscoverTopics": ["renovate", "infrastructure"]}`,
			cicdConf:          "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverTopics",
			wantFilterValue:   `["renovate","infrastructure"]`, // JSON marshaling removes spaces after commas
		},
		{
			name:              "handles quoted values",
			cicdConf:          `RENOVATE_AUTODISCOVER_FILTER: "owner/repo"`,
			configFileContent: "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverFilter",
			wantFilterValue:   "owner/repo",
		},
		{
			name:              "handles single quoted values",
			cicdConf:          `RENOVATE_AUTODISCOVER_FILTER: 'owner/*'`,
			configFileContent: "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverFilter",
			wantFilterValue:   "owner/*",
		},
		{
			name:              "no autodiscovery filters",
			cicdConf:          "RENOVATE_TOKEN: ${{ secrets.TOKEN }}",
			configFileContent: `{"extends": ["config:base"]}`,
			wantHasFilters:    false,
			wantFilterType:    "",
			wantFilterValue:   "",
		},
		{
			name:              "handles colon separator",
			cicdConf:          "autodiscoverFilter: owner/repo",
			configFileContent: "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverFilter",
			wantFilterValue:   "owner/repo",
		},
		{
			name:              "handles equals separator",
			cicdConf:          "autodiscoverFilter=owner/repo",
			configFileContent: "",
			wantHasFilters:    true,
			wantFilterType:    "autodiscoverFilter",
			wantFilterValue:   "owner/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasFilters, filterType, filterValue := DetectAutodiscoveryFilters(tt.cicdConf, tt.configFileContent)
			assert.Equal(t, tt.wantHasFilters, hasFilters)
			assert.Equal(t, tt.wantFilterType, filterType)
			assert.Equal(t, tt.wantFilterValue, filterValue)
		})
	}
}

func TestExtractSelfHostedOptions(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{
			name: "extracts options from markdown headers",
			data: []byte(`# Self-hosted Configuration

## allowCustomCrateRegistries

Some description here.

## allowPostUpgradeCommandTemplating

Another option description.

## allowScripts

Yet another option.
`),
			want: []string{
				"allowCustomCrateRegistries",
				"allowPostUpgradeCommandTemplating",
				"allowScripts",
			},
		},
		{
			name: "handles empty content",
			data: []byte(""),
			want: nil,
		},
		{
			name: "handles no headers",
			data: []byte("Some content without headers"),
			want: nil,
		},
		{
			name: "extracts multiple options",
			data: []byte(`## option1
## option2
## option3
## option4`),
			want: []string{"option1", "option2", "option3", "option4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSelfHostedOptions(tt.data)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsSelfHostedConfig(t *testing.T) {
	tests := []struct {
		name              string
		config            string
		selfHostedOptions []string
		want              bool
	}{
		{
			name:   "detects self-hosted option",
			config: `{"allowScripts": true}`,
			selfHostedOptions: []string{
				"allowScripts",
				"allowCustomCrateRegistries",
			},
			want: true,
		},
		{
			name:   "case insensitive detection",
			config: `{"ALLOWSCRIPTS": true}`,
			selfHostedOptions: []string{
				"allowScripts",
			},
			want: true,
		},
		{
			name:   "no self-hosted options",
			config: `{"extends": ["config:base"]}`,
			selfHostedOptions: []string{
				"allowScripts",
				"allowCustomCrateRegistries",
			},
			want: false,
		},
		{
			name:              "empty self-hosted options list",
			config:            `{"allowScripts": true}`,
			selfHostedOptions: []string{},
			want:              false,
		},
		{
			name:   "multiple options, finds one",
			config: `{"repositories": [], "allowCustomCrateRegistries": true}`,
			selfHostedOptions: []string{
				"allowScripts",
				"allowCustomCrateRegistries",
				"privateKey",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSelfHostedConfig(tt.config, tt.selfHostedOptions)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRenovateConfigFiles(t *testing.T) {
	t.Run("returns list of config file paths", func(t *testing.T) {
		files := RenovateConfigFiles()

		assert.NotEmpty(t, files)
		assert.Contains(t, files, "renovate.json")
		assert.Contains(t, files, "renovate.json5")
		assert.Contains(t, files, ".github/renovate.json")
		assert.Contains(t, files, ".github/renovate.json5")
		assert.Contains(t, files, ".gitlab/renovate.json")
		assert.Contains(t, files, ".gitlab/renovate.json5")
		assert.Contains(t, files, ".renovaterc")
		assert.Contains(t, files, ".renovaterc.json")
		assert.Contains(t, files, ".renovaterc.json5")
		assert.Contains(t, files, "config.js")
	})

	t.Run("returns consistent results", func(t *testing.T) {
		files1 := RenovateConfigFiles()
		files2 := RenovateConfigFiles()
		assert.Equal(t, files1, files2)
	})
}

// TestFetchCurrentSelfHostedOptions_ReturnsCache verifies that non-empty cached options
// are returned immediately without making an HTTP request.
func TestFetchCurrentSelfHostedOptions_ReturnsCache(t *testing.T) {
	cached := []string{"platform", "endpoint"}
	// Use a real client - it will never be invoked since the cache returns early
	result := FetchCurrentSelfHostedOptions(cached, httpclient.GetPipeleekHTTPClient("", nil, nil))
	assert.Equal(t, cached, result)
}

// TestFetchCurrentSelfHostedOptions_ParsesResponse verifies that options are extracted
// from a mock HTTP server response.
func TestFetchCurrentSelfHostedOptions_ParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("## platform\n## endpoint\n## binarySource\n"))
	}))
	defer srv.Close()

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	client.HTTPClient.Transport = &redirectTransport{targetURL: srv.URL}

	result := FetchCurrentSelfHostedOptions([]string{}, client)
	assert.NotEmpty(t, result)
}

// TestFetchCurrentSelfHostedOptions_Non200 verifies that an empty list is returned
// when the server responds with a non-200 status.
func TestFetchCurrentSelfHostedOptions_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use 404: the retryablehttp client does not retry 4xx client errors by default
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	client.HTTPClient.Transport = &redirectTransport{targetURL: srv.URL}

	result := FetchCurrentSelfHostedOptions([]string{}, client)
	assert.Empty(t, result)
}

// TestExtendRenovateConfig_Success verifies that a successful response replaces the config.
func TestExtendRenovateConfig_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/resolve", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"extends":["config:base","security:openssf-scorecard"]}`))
	}))
	defer srv.Close()

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	result := ExtendRenovateConfig(`{"extends":["config:base"]}`, srv.URL, "https://gitlab.example.com/org/repo", client)
	assert.Equal(t, `{"extends":["config:base","security:openssf-scorecard"]}`, result)
}

// TestExtendRenovateConfig_BadURL verifies that the original config is returned on URL parse error.
func TestExtendRenovateConfig_BadURL(t *testing.T) {
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	orig := `{"extends":["config:base"]}`
	result := ExtendRenovateConfig(orig, "://bad-url", "https://project.example.com", client)
	assert.Equal(t, orig, result)
}

// TestExtendRenovateConfig_RequestError verifies that the original config is returned on error.
func TestExtendRenovateConfig_RequestError(t *testing.T) {
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	client.RetryMax = 0
	orig := `{"extends":["config:base"]}`
	result := ExtendRenovateConfig(orig, "http://127.0.0.1:0", "https://project.example.com", client)
	assert.Equal(t, orig, result)
}

// TestValidateRenovateConfigService_Success verifies that a healthy service returns nil error.
func TestValidateRenovateConfigService_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	err := ValidateRenovateConfigService(srv.URL, client)
	assert.NoError(t, err)
}

// TestValidateRenovateConfigService_Non200 verifies that a non-200 response returns an error.
func TestValidateRenovateConfigService_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use 404: the retryablehttp client does not retry 4xx client errors by default
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	err := ValidateRenovateConfigService(srv.URL, client)
	assert.Error(t, err)
}

// TestValidateRenovateConfigService_BadURL verifies that an unparseable URL returns an error.
func TestValidateRenovateConfigService_BadURL(t *testing.T) {
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	err := ValidateRenovateConfigService("://bad-url", client)
	assert.Error(t, err)
}

// TestValidateRenovateConfigService_Unreachable verifies that an unreachable host returns an error.
func TestValidateRenovateConfigService_Unreachable(t *testing.T) {
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	client.RetryMax = 0
	err := ValidateRenovateConfigService("http://127.0.0.1:0", client)
	assert.Error(t, err)
}

// redirectTransport is a test helper that redirects all requests to a fixed target URL,
// preserving path/query from the original request.
type redirectTransport struct {
	targetURL string
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	parsed, err := http.NewRequest(req.Method, t.targetURL+req.URL.Path, req.Body)
	if err != nil {
		return nil, err
	}
	parsed.Header = req.Header
	return http.DefaultTransport.RoundTrip(parsed)
}
