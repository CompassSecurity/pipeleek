package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
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
	Threads               int      `mapstructure:"threads"`
	TruffleHogVerification bool     `mapstructure:"trufflehog_verification"`
	MaxArtifactSize       string   `mapstructure:"max_artifact_size"`
	ConfidenceFilter      []string `mapstructure:"confidence_filter"`
	HitTimeout            string   `mapstructure:"hit_timeout"`
}

var globalViper *viper.Viper

// InitializeViper initializes the global Viper instance with config file and defaults.
// This should be called once during application initialization.
func InitializeViper(configFile string) error {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// If a config file is explicitly specified, use it
	if configFile != "" {
		v.SetConfigFile(configFile)
		log.Debug().Str("path", configFile).Msg("Using specified config file")
	} else {
		// Look for config in standard locations
		v.SetConfigName("pipeleek")
		v.SetConfigType("yaml")
		
		// Add config paths
		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(filepath.Join(home, ".config", "pipeleek"))
			v.AddConfigPath(home)
		}
		v.AddConfigPath(".")
		
		log.Debug().Msg("Searching for config file in standard locations")
	}

	// Read config file (if it exists)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; using defaults and flags
			log.Debug().Msg("No config file found, using defaults and command-line flags")
		} else {
			// Config file was found but another error was encountered
			return fmt.Errorf("error reading config file: %w", err)
		}
	} else {
		log.Info().Str("file", v.ConfigFileUsed()).Msg("Loaded config file")
	}

	// Read from environment variables with PIPELEEK_ prefix
	v.SetEnvPrefix("PIPELEEK")
	v.AutomaticEnv()

	globalViper = v
	return nil
}

// GetViper returns the global Viper instance
func GetViper() *viper.Viper {
	if globalViper == nil {
		// If Viper hasn't been initialized, initialize with defaults
		if err := InitializeViper(""); err != nil {
			log.Fatal().Err(err).Msg("Failed to auto-initialize Viper configuration")
		}
	}
	return globalViper
}

// BindFlags binds command flags to Viper configuration keys.
// This enables automatic priority handling: CLI flags > config file > defaults.
func BindFlags(cmd *cobra.Command, flagMappings map[string]string) error {
	v := GetViper()
	for flagName, viperKey := range flagMappings {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			// Try parent flags
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

// GetString retrieves a string value using Viper's native priority handling
func GetString(key string) string {
	return GetViper().GetString(key)
}

// GetBool retrieves a bool value using Viper's native priority handling
func GetBool(key string) bool {
	return GetViper().GetBool(key)
}

// GetInt retrieves an int value using Viper's native priority handling
func GetInt(key string) int {
	return GetViper().GetInt(key)
}

// GetStringSlice retrieves a string slice using Viper's native priority handling
func GetStringSlice(key string) []string {
	return GetViper().GetStringSlice(key)
}

// UnmarshalConfig unmarshals the configuration into a Config struct
func UnmarshalConfig() (*Config, error) {
	config := &Config{}
	if err := GetViper().Unmarshal(config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}
	return config, nil
}

// setDefaults sets default values for all configuration options
func setDefaults(v *viper.Viper) {
	// Common defaults
	v.SetDefault("common.threads", 4)
	v.SetDefault("common.trufflehog_verification", true)
	v.SetDefault("common.max_artifact_size", "500Mb")
	v.SetDefault("common.confidence_filter", []string{})
	v.SetDefault("common.hit_timeout", "60s")

	// GitHub defaults
	v.SetDefault("github.url", "https://api.github.com")
}

