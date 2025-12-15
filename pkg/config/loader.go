package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
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

var globalConfig *Config

// LoadConfig loads configuration from a file if specified, otherwise uses defaults.
// The configFile parameter can be empty, in which case it will look for config files
// in standard locations (~/.pipeleek.yaml, ~/.config/pipeleek/config.yaml, etc.)
func LoadConfig(configFile string) (*Config, error) {
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
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	} else {
		log.Info().Str("file", v.ConfigFileUsed()).Msg("Loaded config file")
	}

	// Read from environment variables with PIPELEEK_ prefix
	v.SetEnvPrefix("PIPELEEK")
	v.AutomaticEnv()

	config := &Config{}
	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	globalConfig = config
	return config, nil
}

// GetConfig returns the global configuration instance
func GetConfig() *Config {
	if globalConfig == nil {
		// If config hasn't been loaded, load with defaults
		config, err := LoadConfig("")
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to load config")
		}
		return config
	}
	return globalConfig
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


