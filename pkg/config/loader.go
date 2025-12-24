package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Config represents the complete configuration structure for pipeleek.
// It supports configuration for all platforms and common settings.
type Config struct {
	GitLab      GitLabConfig      `mapstructure:"gitlab"`
	GitHub      GitHubConfig      `mapstructure:"github"`
	BitBucket   BitBucketConfig   `mapstructure:"bitbucket"`
	AzureDevOps AzureDevOpsConfig `mapstructure:"azure_devops"`
	Gitea       GiteaConfig       `mapstructure:"gitea"`
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

// BindCommandFlags binds a command's flags (including inherited ones) to Viper keys.
// Keys are derived from the provided baseKey plus the normalized flag name, unless
// an override is provided in the overrides map (flag name -> viper key).
//
// Example:
//
//	BindCommandFlags(cmd, "gitlab.scan", map[string]string{"gitlab": "gitlab.url"})
//	--threads -> gitlab.scan.threads
//	--gitlab  -> gitlab.url (override)
func BindCommandFlags(cmd *cobra.Command, baseKey string, overrides map[string]string) error {
	v := GetViper()

	seen := make(map[string]struct{})
	flagSets := []*pflag.FlagSet{cmd.Flags(), cmd.InheritedFlags(), cmd.PersistentFlags()}

	for _, fs := range flagSets {
		if fs == nil {
			continue
		}
		fs.VisitAll(func(flag *pflag.Flag) {
			if flag == nil {
				return
			}
			if _, ok := seen[flag.Name]; ok {
				return
			}
			seen[flag.Name] = struct{}{}

			key := baseKey + "." + normalizeFlagKey(flag.Name)
			if override, ok := overrides[flag.Name]; ok {
				key = override
			}

			if err := v.BindPFlag(key, flag); err != nil {
				log.Fatal().Err(err).Str("flag", flag.Name).Str("key", key).Msg("Failed to bind flag")
			}
		})
	}

	return nil
}

func InitializeViper(configFile string) error {
	v := viper.New()

	setDefaults(v)

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
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
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
				return fmt.Errorf("error reading config file: %w", err)
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
	v.SetDefault("bitbucket.url", "https://bitbucket.org")
	v.SetDefault("azure_devops.url", "https://dev.azure.com")
}

// AutoBindFlags automatically binds all flags from a command to Viper using the provided key mappings.
func AutoBindFlags(cmd *cobra.Command, flagMappings map[string]string) error {
	v := GetViper()

	for flagName, viperKey := range flagMappings {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			flag = cmd.InheritedFlags().Lookup(flagName)
		}
		if flag != nil {
			if err := v.BindPFlag(viperKey, flag); err != nil {
				return fmt.Errorf("failed to bind flag %s to key %s: %w", flagName, viperKey, err)
			}
		}
	}
	return nil
}

// RequireConfigKeys validates that all required configuration keys have non-empty values.
// This allows flags to be satisfied by either CLI flags or config file values.
// Call this after AutoBindFlags to validate required values from any source.
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
