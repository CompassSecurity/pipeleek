package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the complete configuration structure for pipeleek.
// It supports configuration for all platforms and common settings.
type Config struct {
	GitLab      GitLabConfig      `mapstructure:"gitlab"`
	GitHub      GitHubConfig      `mapstructure:"github"`
	BitBucket   BitBucketConfig   `mapstructure:"bitbucket"`
	AzureDevOps AzureDevOpsConfig `mapstructure:"azure_devops"`
	Gitea       GiteaConfig       `mapstructure:"gitea"`
	Jenkins     JenkinsConfig     `mapstructure:"jenkins"`
	Common      CommonConfig      `mapstructure:"common"`
}

// GitLabConfig contains GitLab-specific configuration
type GitLabConfig struct {
	URL    string `mapstructure:"url"`
	Token  string `mapstructure:"token"`
	Cookie string `mapstructure:"cookie"`
}

// GitHubConfig contains GitHub-specific configuration
type GitHubConfig struct {
	URL   string `mapstructure:"url"`
	Token string `mapstructure:"token"`
}

// BitBucketConfig contains BitBucket-specific configuration
type BitBucketConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// AzureDevOpsConfig contains Azure DevOps-specific configuration
type AzureDevOpsConfig struct {
	URL   string `mapstructure:"url"`
	Token string `mapstructure:"token"`
}

// GiteaConfig contains Gitea-specific configuration
type GiteaConfig struct {
	URL   string `mapstructure:"url"`
	Token string `mapstructure:"token"`
}

type JenkinsConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Token    string `mapstructure:"token"`
}

// CommonConfig contains common configuration settings
type CommonConfig struct {
	Threads                int      `mapstructure:"threads"`
	TruffleHogVerification bool     `mapstructure:"trufflehog_verification"`
	MaxArtifactSize        string   `mapstructure:"max_artifact_size"`
	ConfidenceFilter       []string `mapstructure:"confidence_filter"`
	HitTimeout             string   `mapstructure:"hit_timeout"`
}

var globalViper *viper.Viper

// normalizeFlagKey converts cobra flag names to viper key fragments.
// Example: "max-artifact-size" -> "max_artifact_size".
func normalizeFlagKey(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}

func InitializeViper(configFile string) error {
	v := viper.New()

	setDefaults(v)

	// Allow tests or users to disable config file loading entirely
	noCfg := os.Getenv("PIPELEEK_NO_CONFIG")
	if strings.EqualFold(noCfg, "1") || strings.EqualFold(noCfg, "true") || strings.EqualFold(noCfg, "yes") {
		log.Debug().Msg("Skipping config file loading due to PIPELEEK_NO_CONFIG")
		v.SetEnvPrefix("PIPELEEK")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()
		globalViper = v
		return nil
	}

	if configFile != "" {
		v.SetConfigFile(configFile)
		log.Debug().Str("path", configFile).Msg("Using specified config file")
	} else {
		v.SetConfigName("pipeleek")
		v.SetConfigType("yaml")

		// Get home directory: try HOME/USERPROFILE env vars first (for testing), then os.UserHomeDir()
		home := os.Getenv("HOME")
		if home == "" {
			home = os.Getenv("USERPROFILE") // Windows
		}
		if home == "" {
			var err error
			home, err = os.UserHomeDir()
			if err != nil {
				home = ""
			}
		}

		if home != "" {
			v.AddConfigPath(filepath.Join(home, ".config", "pipeleek"))
			v.AddConfigPath(home)
		}
		// Always add current directory to search path
		v.AddConfigPath(".")

		log.Debug().Msg("Searching for config file in standard locations")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok || os.IsNotExist(err) {
			log.Debug().Msg("No config file found, using defaults and command-line flags")
		} else {
			// Check if Viper tried to read a file without proper extension (like the binary)
			configFileUsed := v.ConfigFileUsed()
			if configFileUsed != "" {
				ext := filepath.Ext(configFileUsed)
				if ext != ".yaml" && ext != ".yml" {
					log.Debug().Str("file", configFileUsed).Msg("Ignoring file without .yaml/.yml extension")
					log.Debug().Msg("No config file found, using defaults and command-line flags")
				} else {
					return fmt.Errorf("error reading config file %s: %w", configFileUsed, err)
				}
			} else {
				// If no file was used, it's likely a parsing error on a non-YAML file
				// Treat this as "no config file found" rather than an error
				log.Debug().Str("error", err.Error()).Msg("Config file parsing failed or not valid YAML; treating as not found")
			}
		}
	} else {
		log.Info().Str("file", v.ConfigFileUsed()).Msg("Loaded config file")
		loadedKeys := v.AllKeys()
		if len(loadedKeys) > 0 {
			log.Trace().Strs("keys", loadedKeys).Msg("Configuration keys loaded from file")
		}
	}

	v.SetEnvPrefix("PIPELEEK")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	globalViper = v
	return nil
}

func GetViper() *viper.Viper {
	if globalViper == nil {
		if err := InitializeViper(""); err != nil {
			log.Fatal().Err(err).Msg("Failed to auto-initialize Viper configuration")
		}
	}
	return globalViper
}

// ResetViper resets the global Viper instance for testing
func ResetViper() {
	globalViper = nil
}

func GetString(key string) string {
	return GetViper().GetString(key)
}

func GetBool(key string) bool {
	return GetViper().GetBool(key)
}

func GetInt(key string) int {
	return GetViper().GetInt(key)
}

func GetStringSlice(key string) []string {
	return GetViper().GetStringSlice(key)
}

func UnmarshalConfig() (*Config, error) {
	config := &Config{}
	if err := GetViper().Unmarshal(config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}
	return config, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("common.threads", 4)
	v.SetDefault("common.trufflehog_verification", true)
	v.SetDefault("common.max_artifact_size", "500Mb")
	v.SetDefault("common.confidence_filter", []string{})
	v.SetDefault("common.hit_timeout", "60s")

	v.SetDefault("github.url", "https://api.github.com")
	v.SetDefault("bitbucket.url", "https://api.bitbucket.org/2.0")
	v.SetDefault("azure_devops.url", "https://dev.azure.com")
}

// RequireConfigKeys validates that all required configuration keys have non-empty values.
// This allows flags to be satisfied by either CLI flags or config file values.
func RequireConfigKeys(keys ...string) error {
	v := GetViper()
	var missing []string

	for _, key := range keys {
		value := v.GetString(key)
		if value == "" {
			missing = append(missing, key)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("required configuration missing: %v (provide via flags or config file)", missing)
	}

	return nil
}

// GetEffectiveConfigPath returns the path to the resolved config file, searching the standard
// locations if no explicit config file was configured. Returns "" if no config file was found.
func GetEffectiveConfigPath(explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}

	v := GetViper()
	configFileUsed := v.ConfigFileUsed()
	if configFileUsed != "" {
		ext := strings.ToLower(filepath.Ext(configFileUsed))
		if ext != ".yaml" && ext != ".yml" {
			configFileUsed = ""
		}
	}
	if configFileUsed != "" {
		return configFileUsed
	}

	// If no config file was found yet, resolve the default location
	home := os.Getenv("HOME")
	if home == "" {
		home = os.Getenv("USERPROFILE") // Windows
	}
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			home = ""
		}
	}

	// Prefer ~/.config/pipeleek/pipeleek.yaml as the default write location
	if home != "" {
		return filepath.Join(home, ".config", "pipeleek", "pipeleek.yaml")
	}

	// Fallback to current directory
	return filepath.Join(".", "pipeleek.yaml")
}

// LoadConfigFile reads a YAML config file into a mutable map. If the file does not exist
// or is empty, returns an empty map and no error.
func LoadConfigFile(path string) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	// If no path or file doesn't exist, return empty map (not an error)
	if path == "" {
		return data, nil
	}

	content, err := os.ReadFile(path) // #nosec G304 -- path is an explicit user-selected config file location
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// If content is empty or only whitespace, return empty map
	contentStr := strings.TrimSpace(string(content))
	if contentStr == "" {
		return data, nil
	}

	// Parse YAML content directly using viper
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(contentStr)); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Get all settings from viper as a map
	data = v.AllSettings()
	return data, nil
}

// GetByPath retrieves a value from a nested map using dotted key notation.
// Example: "gitlab.runners.exploit.tags" navigates the nested structure.
// Returns the value (which may be a map, slice, string, etc.) and true if found.
// Returns nil and false if the key or any parent does not exist.
func GetByPath(data map[string]interface{}, path string) (interface{}, bool) {
	if path == "" {
		return data, true
	}

	segments := strings.Split(path, ".")
	current := interface{}(data)

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		switch v := current.(type) {
		case map[string]interface{}:
			val, ok := v[segment]
			if !ok {
				return nil, false
			}
			current = val
		default:
			// Attempting to descend through a non-map (scalar or list)
			return nil, false
		}
	}

	return current, true
}

// SetByPath sets a value in a nested map using dotted key notation, creating missing parent maps as needed.
// Example: "gitlab.runners.exploit.tags" creates the intermediate maps gitlab → runners → exploit and sets tags.
// Returns an error if attempting to descend through a non-map scalar value.
func SetByPath(data map[string]interface{}, path string, value interface{}) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	segments := strings.Split(path, ".")
	if len(segments) == 0 {
		return fmt.Errorf("path has no segments")
	}

	// Navigate to the parent, creating maps as needed
	current := data
	for i := 0; i < len(segments)-1; i++ {
		segment := segments[i]
		if segment == "" {
			continue
		}

		if val, ok := current[segment]; !ok {
			// Create a new map for this segment
			current[segment] = make(map[string]interface{})
			current = current[segment].(map[string]interface{})
		} else if m, ok := val.(map[string]interface{}); ok {
			// Descend into existing map
			current = m
		} else {
			// Attempting to descend through a non-map
			return fmt.Errorf("cannot set %s: path traversal blocked by non-map value at %s", path, segments[i])
		}
	}

	// Set the final key
	lastSegment := segments[len(segments)-1]
	if lastSegment != "" {
		current[lastSegment] = value
	}

	return nil
}

// WriteConfigFile writes a config map back to a file as deterministic YAML.
// It uses the yaml.v3 encoder with sorted key output to ensure consistent file ordering.
func WriteConfigFile(path string, data map[string]interface{}) (string, error) {
	if path == "" {
		return "", fmt.Errorf("config file path cannot be empty")
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("failed to create parent directory: %w", err)
	}

	// Use yaml.v3 encoder for deterministic output
	content, err := marshalConfigToYAML(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("failed to write config file: %w", err)
	}

	return path, nil
}

// marshalConfigToYAML converts a config map to YAML string with sorted key output for determinism.
func marshalConfigToYAML(data map[string]interface{}) (string, error) {
	node, err := toSortedYAMLNode(data)
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(node); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// toSortedYAMLNode converts a map to a yaml.Node with alphabetically sorted keys.
func toSortedYAMLNode(data map[string]interface{}) (*yaml.Node, error) {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	mapping := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, k := range keys {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}
		valNode, err := toYAMLNode(data[k])
		if err != nil {
			return nil, err
		}
		mapping.Content = append(mapping.Content, keyNode, valNode)
	}
	return mapping, nil
}

// toYAMLNode converts any config value to a yaml.Node.
func toYAMLNode(value interface{}) (*yaml.Node, error) {
	switch v := value.(type) {
	case map[string]interface{}:
		return toSortedYAMLNode(v)
	default:
		var node yaml.Node
		if err := node.Encode(value); err != nil {
			return nil, err
		}
		// Encode wraps in a document node; unwrap it
		if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
			return node.Content[0], nil
		}
		return &node, nil
	}
}
