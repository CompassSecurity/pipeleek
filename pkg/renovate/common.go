package renovate

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/rs/zerolog/log"
	"github.com/yosuke-furukawa/json5/encoding/json5"
	"gopkg.in/yaml.v3"
	"resty.dev/v3"
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

var (
	disabledAutodiscoverFlag   = regexp.MustCompile(`(?i)--autodiscover(?:\s*=\s*|\s+)(?:"false"|'false'|false)(?:\s|["']|$)`)
	disabledAutodiscoverEnv    = regexp.MustCompile(`(?im)(?:^|[^A-Z0-9_])RENOVATE_AUTODISCOVER\s*(?::|=)\s*(?:"false"|'false'|false)(?:\s|["']|#|$)`)
	disabledAutodiscoverConfig = regexp.MustCompile(`(?im)(?:^|[,{;\s])["']?autodiscover["']?\s*[:=]\s*(?:"false"|'false'|false)(?:\s*[,;}#]|$)`)
)

// DetectAutodiscovery checks for autodiscover configuration in CI/CD or config files.
func DetectAutodiscovery(cicdConf string, configFileContent string) bool {
	hasAutodiscoveryInConfigFile := format.ContainsI(configFileContent, "autodiscover") &&
		!disabledAutodiscoverConfig.MatchString(configFileContent)

	hasAutodiscoveryinCiCD := (format.ContainsI(cicdConf, "--autodiscover") || format.ContainsI(cicdConf, "RENOVATE_AUTODISCOVER")) &&
		!disabledAutodiscoverFlag.MatchString(cicdConf) && !disabledAutodiscoverEnv.MatchString(cicdConf)

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
	found, filterType, filterValue, _ := DetectAutodiscoveryFiltersWithSource(cicdConf, configFileContent)
	return found, filterType, filterValue
}

// DetectAutodiscoveryFiltersWithSource additionally reports whether an autodiscoverFilter value came from env or CLI input, where commas delimit patterns.
func DetectAutodiscoveryFiltersWithSource(cicdConf, configFileContent string) (bool, string, string, bool) {
	return detectAutodiscoveryFilterGroup(cicdConf, configFileContent, "")
}

type AutodiscoveryScopeOption struct {
	Type           string
	Value          string
	CommaDelimited bool
}

func DetectAutodiscoveryScopeOptions(cicdConf string, configContents []string) []AutodiscoveryScopeOption {
	var options []AutodiscoveryScopeOption
	for _, optionType := range []string{"autodiscoverFilter", "autodiscoverNamespaces", "autodiscoverProjects", "autodiscoverTopics"} {
		found, _, value, commaDelimited := detectAutodiscoveryFilterGroup(cicdConf, "", optionType)
		if !found {
			for _, content := range configContents {
				found, _, value, commaDelimited = detectAutodiscoveryFilterGroup("", content, optionType)
				if found {
					break
				}
			}
		}
		if found {
			options = append(options, AutodiscoveryScopeOption{Type: optionType, Value: value, CommaDelimited: commaDelimited})
		}
	}
	return options
}

func detectCICDVariable(content, name string) (string, bool) {
	var document yaml.Node
	if yaml.Unmarshal([]byte(content), &document) != nil {
		return "", false
	}
	var find func(*yaml.Node) (string, bool)
	find = func(node *yaml.Node) (string, bool) {
		if node.Kind == yaml.MappingNode {
			for index := 0; index+1 < len(node.Content); index += 2 {
				key, value := node.Content[index], node.Content[index+1]
				if key.Value == "variables" && value.Kind == yaml.MappingNode {
					for variableIndex := 0; variableIndex+1 < len(value.Content); variableIndex += 2 {
						if value.Content[variableIndex].Value != name {
							continue
						}
						variable := value.Content[variableIndex+1]
						if variable.Kind == yaml.MappingNode {
							for fieldIndex := 0; fieldIndex+1 < len(variable.Content); fieldIndex += 2 {
								if variable.Content[fieldIndex].Value == "value" && variable.Content[fieldIndex+1].Kind == yaml.ScalarNode {
									return variable.Content[fieldIndex+1].Value, true
								}
							}
							return "", true
						}
						if variable.Kind == yaml.ScalarNode && variable.Tag != "!!null" {
							return variable.Value, true
						}
						return "", true
					}
				}
				if foundValue, found := find(value); found {
					return foundValue, true
				}
			}
		} else {
			for _, child := range node.Content {
				if foundValue, found := find(child); found {
					return foundValue, true
				}
			}
		}
		return "", false
	}
	return find(&document)
}

func DetectAutodiscoveryCICDSetting(content string) (bool, bool) {
	value, found := detectCICDVariable(content, "RENOVATE_AUTODISCOVER")
	if !found {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func detectAutodiscoveryFilterGroup(cicdConf, configFileContent, optionType string) (bool, string, string, bool) {
	type groupDef struct {
		name string
		keys []string
	}

	groups := []groupDef{
		{"autodiscoverFilter", []string{"autodiscoverFilter", "--autodiscover-filter", "RENOVATE_AUTODISCOVER_FILTER"}},
		{"autodiscoverNamespaces", []string{"autodiscoverNamespaces", "--autodiscover-namespaces", "RENOVATE_AUTODISCOVER_NAMESPACES"}},
		{"autodiscoverProjects", []string{"autodiscoverProjects", "--autodiscover-projects", "RENOVATE_AUTODISCOVER_PROJECTS"}},
		{"autodiscoverTopics", []string{"autodiscoverTopics", "--autodiscover-topics", "RENOVATE_AUTODISCOVER_TOPICS"}},
	}

	sources := []string{configFileContent, cicdConf}

	for _, g := range groups {
		if optionType != "" && g.name != optionType {
			continue
		}
		for _, src := range sources {
			if strings.TrimSpace(src) == "" {
				continue
			}
			for _, key := range g.keys {
				if strings.HasPrefix(key, "RENOVATE_") || strings.HasPrefix(key, "--") {
					continue
				}
				if val, ok := tryParseJSON(src, key); ok {
					return true, g.name, val, false
				}
			}
		}

		for _, key := range g.keys {
			if key == "--autodiscover-filter" || key == "RENOVATE_AUTODISCOVER_FILTER" || key == "--autodiscover-namespaces" || key == "RENOVATE_AUTODISCOVER_NAMESPACES" {
				separator := `\s*(?:=|\s+)\s*`
				if strings.HasPrefix(key, "RENOVATE_") {
					separator = `\s*(?:=|:)\s*`
				}
				re := regexp.MustCompile(`(?is)` + regexp.QuoteMeta(key) + separator + `(?:([^\s"']*\$\{\{[^}]*\}\}[^\s"']*)|"([^"]*)"|'([^']*)'|([^\s"']+))`)
				for sourceIndex, src := range sources {
					if sourceIndex == 1 && strings.HasPrefix(key, "RENOVATE_") {
						if value, found := detectCICDVariable(src, key); found {
							return true, g.name, value, true
						}
					}
					if m := re.FindStringSubmatch(src); len(m) > 0 {
						for _, value := range m[1:] {
							if value != "" {
								return true, g.name, value, sourceIndex == 1
							}
						}
						return true, g.name, "", sourceIndex == 1
					}
				}
				continue
			}
			re := regexp.MustCompile(`(?is)` + regexp.QuoteMeta(key) + `\s*[:= ]\s*(\[[^\]]*\]|"[^"]*"|'[^']*'|[^\s,]*\$\{\{[^\}]*\}\}[^\s,]*|\{[^\}]*\}|[^\s,"']+)`)
			for sourceIndex, src := range sources {
				if sourceIndex == 1 && strings.HasPrefix(key, "RENOVATE_") {
					if value, found := detectCICDVariable(src, key); found {
						return true, g.name, value, false
					}
				}
				if m := re.FindStringSubmatch(src); len(m) > 1 {
					val := strings.TrimSpace(m[1])
					if (strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`)) ||
						(strings.HasPrefix(val, `'`) && strings.HasSuffix(val, `'`)) {
						val = val[1 : len(val)-1]
					}
					return true, g.name, val, g.name == "autodiscoverFilter" && sourceIndex == 1 && (strings.HasPrefix(key, "RENOVATE_") || strings.HasPrefix(key, "--"))
				}
			}
		}
	}
	return false, "", "", false
}

// FetchCurrentSelfHostedOptions retrieves the list of self-hosted Renovate configuration options.
// Accepts a Resty client to allow injection for testing.
func FetchCurrentSelfHostedOptions(cachedOptions []string, client *resty.Client) []string {
	if len(cachedOptions) > 0 {
		return cachedOptions
	}

	log.Debug().Msg("Fetching current self-hosted configuration from GitHub")

	res, err := client.R().Get("https://raw.githubusercontent.com/renovatebot/renovate/refs/heads/main/docs/usage/self-hosted-configuration.md")
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed fetching self-hosted configuration documentation")
		return []string{}
	}
	if res.StatusCode() != 200 {
		log.Error().Int("status", res.StatusCode()).Msg("Failed fetching self-hosted configuration documentation")
		return []string{}
	}

	return ExtractSelfHostedOptions(res.Bytes())
}

// ExtractSelfHostedOptions parses self-hosted options from documentation content.
func ExtractSelfHostedOptions(data []byte) []string {
	var re = regexp.MustCompile(`(?m)## .*`)
	matches := re.FindAllString(string(data), -1)

	var options []string
	for _, match := range matches {
		option := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(match), "##"))
		option = strings.Trim(option, "`")
		if option != "" {
			options = append(options, option)
		}
	}

	return options
}

var selfHostedOptionWordBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// IsSelfHostedConfig checks if a Renovate configuration contains self-hosted options.
func IsSelfHostedConfig(config string, selfHostedOptions []string) bool {
	for _, rawOption := range selfHostedOptions {
		option := strings.Trim(strings.TrimSpace(rawOption), "`")
		if option == "" {
			continue
		}
		snakeCaseOption := selfHostedOptionWordBoundary.ReplaceAllString(option, `${1}_${2}`)
		aliases := []string{
			option,
			"RENOVATE_" + strings.ToUpper(snakeCaseOption),
			"--" + strings.ReplaceAll(strings.ToLower(snakeCaseOption), "_", "-"),
		}
		for _, alias := range aliases {
			if format.ContainsI(config, alias) {
				return true
			}
		}
	}
	return false
}

// ExtendRenovateConfig extends a Renovate configuration by sending it to a resolver service.
// The config is normalized to valid JSON before sending (removes JSON5 comments/trailing commas).
// Accepts a Resty client to allow injection for testing.
func ExtendRenovateConfig(renovateConfig string, serviceURL string, projectURL string, client *resty.Client) string {
	u, err := url.Parse(serviceURL)
	if err != nil {
		log.Error().Stack().Err(err).Str("project", projectURL).Msg("Failed to parse renovate config service URL")
		return renovateConfig
	}
	u = u.JoinPath("resolve")

	normalizedConfig := normalizeRenovateConfig(renovateConfig)

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(normalizedConfig).
		Post(u.String())

	if err != nil {
		log.Error().Stack().Err(err).Str("project", projectURL).Msg("Failed to extend renovate config")
		return renovateConfig
	}

	bodyBytes := resp.Bytes()

	if resp.StatusCode() != 200 {
		log.Debug().Int("status", resp.StatusCode()).Str("msg", string(bodyBytes)).Str("project", projectURL).Msg("Failed to extend renovate config")
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
// Accepts a Resty client to allow injection for testing.
func ValidateRenovateConfigService(serviceUrl string, client *resty.Client) error {
	u, err := url.Parse(serviceUrl)
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed to parse renovate config service URL")
		return err
	}
	u = u.JoinPath("health")

	resp, err := client.R().Get(u.String())

	if err != nil {
		log.Error().Stack().Err(err).Msg("Renovate config service healthcheck failed")
		return err
	}

	if resp.StatusCode() != 200 {
		log.Error().Int("status", resp.StatusCode()).Str("endpoint", u.String()).Msg("Renovate config service healthcheck failed")
		return fmt.Errorf("renovate config service healthcheck failed: %d", resp.StatusCode())
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
