package renovate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog/log"
	"github.com/yosuke-furukawa/json5/encoding/json5"
)

// DetectCiCdConfig checks if the CI/CD configuration contains Renovate bot references.
func DetectCiCdConfig(cicdConf string) bool {
	return format.ContainsI(cicdConf, "renovate/renovate") ||
		format.ContainsI(cicdConf, "renovatebot/renovate") ||
		format.ContainsI(cicdConf, "renovatebot/github-action") ||
		format.ContainsI(cicdConf, "renovate-bot/renovate-runner") ||
		format.ContainsI(cicdConf, "RENOVATE_") ||
		format.ContainsI(cicdConf, "npx renovate")
}

// DetectAutodiscovery checks for autodiscover configuration in CI/CD or config files.
func DetectAutodiscovery(cicdConf string, configFileContent string) bool {
	hasAutodiscoveryInConfigFile := format.ContainsI(configFileContent, "autodiscover")

	hasAutodiscoveryinCiCD := (format.ContainsI(cicdConf, "--autodiscover") || format.ContainsI(cicdConf, "RENOVATE_AUTODISCOVER")) &&
		(!format.ContainsI(cicdConf, "--autodiscover=false") && !format.ContainsI(cicdConf, "--autodiscover false") && !format.ContainsI(cicdConf, "RENOVATE_AUTODISCOVER: false") && !format.ContainsI(cicdConf, "RENOVATE_AUTODISCOVER=false"))

	return hasAutodiscoveryInConfigFile || hasAutodiscoveryinCiCD
}

// tryParseJSON attempts to parse JSON and extract a value for the given key.
// Returns (value, true) if found, ("", false) otherwise.
func tryParseJSON(jsonStr, key string) (string, bool) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return "", false
	}

	val, ok := data[key]
	if !ok {
		return "", false
	}

	switch v := val.(type) {
	case string:
		return v, true
	case []interface{}:
		if bytes, err := json.Marshal(v); err == nil {
			return string(bytes), true
		}
	case map[string]interface{}:
		if bytes, err := json.Marshal(v); err == nil {
			return string(bytes), true
		}
	default:
		return fmt.Sprintf("%v", v), true
	}

	return "", false
}

// DetectAutodiscoveryFilters checks for autodiscovery filter configuration and returns whether filters exist, filter type, and filter value.
func DetectAutodiscoveryFilters(cicdConf, configFileContent string) (bool, string, string) {
	type groupDef struct {
		name string
		keys []string
	}

	groups := []groupDef{
		{"autodiscoverFilter", []string{"autodiscoverFilter", "RENOVATE_AUTODISCOVER_FILTER", "--autodiscover-filter"}},
		{"autodiscoverNamespaces", []string{"autodiscoverNamespaces", "RENOVATE_AUTODISCOVER_NAMESPACES", "--autodiscover-namespaces"}},
		{"autodiscoverProjects", []string{"autodiscoverProjects", "RENOVATE_AUTODISCOVER_PROJECTS", "--autodiscover-projects"}},
		{"autodiscoverTopics", []string{"autodiscoverTopics", "RENOVATE_AUTODISCOVER_TOPICS", "--autodiscover-topics"}},
	}

	sources := []string{configFileContent, cicdConf}

	for _, g := range groups {
		for _, src := range sources {
			if strings.TrimSpace(src) == "" {
				continue
			}
			for _, key := range g.keys {
				if strings.HasPrefix(key, "RENOVATE_") || strings.HasPrefix(key, "--") {
					continue
				}
				if val, ok := tryParseJSON(src, key); ok {
					return true, g.name, val
				}
			}
		}

		for _, key := range g.keys {
			re := regexp.MustCompile(`(?is)` + regexp.QuoteMeta(key) + `\s*[:= ]\s*(\[[^\]]*\]|"[^"]*"|'[^']*'|[^\s,]*\$\{\{[^\}]*\}\}[^\s,]*|\{[^\}]*\}|[^\s,]+)`)
			for _, src := range sources {
				if m := re.FindStringSubmatch(src); len(m) > 1 {
					val := strings.TrimSpace(m[1])
					if (strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`)) ||
						(strings.HasPrefix(val, `'`) && strings.HasSuffix(val, `'`)) {
						val = val[1 : len(val)-1]
					}
					return true, g.name, val
				}
			}
		}
	}
	return false, "", ""
}

// FetchCurrentSelfHostedOptions retrieves the list of self-hosted Renovate configuration options.
func FetchCurrentSelfHostedOptions(cachedOptions []string) []string {
	if len(cachedOptions) > 0 {
		return cachedOptions
	}

	log.Debug().Msg("Fetching current self-hosted configuration from GitHub")

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	res, err := client.Get("https://raw.githubusercontent.com/renovatebot/renovate/refs/heads/main/docs/usage/self-hosted-configuration.md")
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed fetching self-hosted configuration documentation")
		return []string{}
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 {
		log.Error().Int("status", res.StatusCode).Msg("Failed fetching self-hosted configuration documentation")
		return []string{}
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed reading self-hosted configuration documentation")
		return []string{}
	}

	return ExtractSelfHostedOptions(data)
}

// ExtractSelfHostedOptions parses self-hosted options from documentation content.
func ExtractSelfHostedOptions(data []byte) []string {
	var re = regexp.MustCompile(`(?m)## .*`)
	matches := re.FindAllString(string(data), -1)

	var options []string
	for _, match := range matches {
		options = append(options, strings.ReplaceAll(strings.TrimSpace(match), "## ", ""))
	}

	return options
}

// IsSelfHostedConfig checks if a Renovate configuration contains self-hosted options.
func IsSelfHostedConfig(config string, selfHostedOptions []string) bool {
	for _, option := range selfHostedOptions {
		if format.ContainsI(config, option) {
			return true
		}
	}
	return false
}

// ExtendRenovateConfig extends a Renovate configuration by sending it to a resolver service.
// The config is normalized to valid JSON before sending (removes JSON5 comments/trailing commas).
func ExtendRenovateConfig(renovateConfig string, serviceURL string, projectURL string) string {
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)

	u, err := url.Parse(serviceURL)
	if err != nil {
		log.Error().Stack().Err(err).Str("project", projectURL).Msg("Failed to parse renovate config service URL")
		return renovateConfig
	}
	u = u.JoinPath("resolve")

	normalizedConfig := normalizeRenovateConfig(renovateConfig)

	resp, err := client.Post(u.String(), "application/json", strings.NewReader(normalizedConfig))

	if err != nil {
		log.Error().Stack().Err(err).Str("project", projectURL).Msg("Failed to extend renovate config")
		return renovateConfig
	}

	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Stack().Err(err).Str("project", projectURL).Msg("Failed to read response body of renovate config expansion")
		return renovateConfig
	}

	if resp.StatusCode != 200 {
		log.Debug().Int("status", resp.StatusCode).Str("msg", string(bodyBytes)).Str("project", projectURL).Msg("Failed to extend renovate config")
		return renovateConfig
	}

	return string(bodyBytes)
}

// normalizeRenovateConfig converts a Renovate config (potentially JSON5 with comments/trailing commas)
// to valid JSON by parsing and re-marshaling. This is required before sending to external resolver services
// which only accept valid JSON syntax. Returns the original config if parsing fails.
func normalizeRenovateConfig(config string) string {
	// Try to parse as JSON5 first (handles comments, trailing commas, etc.)
	var data interface{}
	err := json5.Unmarshal([]byte(config), &data)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to parse renovate config as JSON5, trying standard JSON")
		// If JSON5 fails, try standard JSON
		err = json.Unmarshal([]byte(config), &data)
		if err != nil {
			log.Debug().Err(err).Msg("Failed to parse renovate config as JSON, returning original config")
			return config
		}
	}

	// Marshal back to valid JSON (removes comments, normalizes formatting)
	normalized, err := json.Marshal(data)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to marshal normalized renovate config, returning original config")
		return config
	}

	return string(normalized)
}

// ValidateRenovateConfigService checks if the Renovate config resolver service is available.
func ValidateRenovateConfigService(serviceUrl string) error {
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)

	u, err := url.Parse(serviceUrl)
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed to parse renovate config service URL")
		return err
	}
	u = u.JoinPath("health")

	resp, err := client.Get(u.String())

	if err != nil {
		log.Error().Stack().Err(err).Msg("Renovate config service healthcheck failed")
		return err
	}

	if resp.StatusCode != 200 {
		log.Error().Int("status", resp.StatusCode).Str("endpoint", u.String()).Msg("Renovate config service healthcheck failed")
		return fmt.Errorf("renovate config service healthcheck failed: %d", resp.StatusCode)
	}

	return nil
}

// RenovateConfigFiles lists common Renovate configuration file paths.
func RenovateConfigFiles() []string {
	return []string{
		"renovate.json",
		"renovate.json5",
		".github/renovate.json",
		".github/renovate.json5",
		".gitlab/renovate.json",
		".gitlab/renovate.json5",
		".renovaterc",
		".renovaterc.json",
		".renovaterc.json5",
		"config.js",
	}
}
