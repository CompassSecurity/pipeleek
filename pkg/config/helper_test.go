package config

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetStringValue_FlagPriority(t *testing.T) {
	// Reset global config
	globalConfig = &Config{
		GitLab: GitLabConfig{
			URL: "https://config-gitlab.com",
		},
	}
	defer func() { globalConfig = nil }()

	cmd := &cobra.Command{}
	cmd.Flags().String("gitlab", "https://default-gitlab.com", "GitLab URL")

	// Set flag explicitly
	err := cmd.Flags().Set("gitlab", "https://flag-gitlab.com")
	assert.NoError(t, err)

	// Flag should take priority over config
	value := GetStringValue(cmd, "gitlab", func(c *Config) string { return c.GitLab.URL })
	assert.Equal(t, "https://flag-gitlab.com", value)
}

func TestGetStringValue_ConfigPriority(t *testing.T) {
	// Reset global config
	globalConfig = &Config{
		GitLab: GitLabConfig{
			URL: "https://config-gitlab.com",
		},
	}
	defer func() { globalConfig = nil }()

	cmd := &cobra.Command{}
	cmd.Flags().String("gitlab", "https://default-gitlab.com", "GitLab URL")

	// Don't set flag, should use config
	value := GetStringValue(cmd, "gitlab", func(c *Config) string { return c.GitLab.URL })
	assert.Equal(t, "https://config-gitlab.com", value)
}

func TestGetStringValue_DefaultPriority(t *testing.T) {
	// Reset global config
	globalConfig = nil

	cmd := &cobra.Command{}
	cmd.Flags().String("gitlab", "https://default-gitlab.com", "GitLab URL")

	// No config, no flag set, should use default
	value := GetStringValue(cmd, "gitlab", func(c *Config) string {
		if c == nil {
			return ""
		}
		return c.GitLab.URL
	})
	assert.Equal(t, "https://default-gitlab.com", value)
}

func TestGetBoolValue_FlagPriority(t *testing.T) {
	// Reset global config
	globalConfig = &Config{
		Common: CommonConfig{
			TruffleHogVerification: false,
		},
	}
	defer func() { globalConfig = nil }()

	cmd := &cobra.Command{}
	cmd.Flags().Bool("verify", true, "Verify")

	// Set flag explicitly
	err := cmd.Flags().Set("verify", "false")
	assert.NoError(t, err)

	// Flag should take priority over config
	value := GetBoolValue(cmd, "verify", func(c *Config) bool { return c.Common.TruffleHogVerification })
	assert.Equal(t, false, value)
}

func TestGetBoolValue_ConfigPriority(t *testing.T) {
	// Reset global config
	globalConfig = &Config{
		Common: CommonConfig{
			TruffleHogVerification: false,
		},
	}
	defer func() { globalConfig = nil }()

	cmd := &cobra.Command{}
	cmd.Flags().Bool("verify", true, "Verify")

	// Don't set flag, should use config
	value := GetBoolValue(cmd, "verify", func(c *Config) bool { return c.Common.TruffleHogVerification })
	assert.Equal(t, false, value)
}

func TestGetBoolValue_DefaultPriority(t *testing.T) {
	// Reset global config
	globalConfig = nil

	cmd := &cobra.Command{}
	cmd.Flags().Bool("verify", true, "Verify")

	// No config, no flag set, should use default
	value := GetBoolValue(cmd, "verify", func(c *Config) bool {
		if c == nil {
			return true
		}
		return c.Common.TruffleHogVerification
	})
	assert.Equal(t, true, value)
}

func TestGetIntValue_FlagPriority(t *testing.T) {
	// Reset global config
	globalConfig = &Config{
		Common: CommonConfig{
			Threads: 8,
		},
	}
	defer func() { globalConfig = nil }()

	cmd := &cobra.Command{}
	cmd.Flags().Int("threads", 4, "Threads")

	// Set flag explicitly
	err := cmd.Flags().Set("threads", "16")
	assert.NoError(t, err)

	// Flag should take priority over config
	value := GetIntValue(cmd, "threads", func(c *Config) int { return c.Common.Threads })
	assert.Equal(t, 16, value)
}

func TestGetIntValue_ConfigPriority(t *testing.T) {
	// Reset global config
	globalConfig = &Config{
		Common: CommonConfig{
			Threads: 8,
		},
	}
	defer func() { globalConfig = nil }()

	cmd := &cobra.Command{}
	cmd.Flags().Int("threads", 4, "Threads")

	// Don't set flag, should use config
	value := GetIntValue(cmd, "threads", func(c *Config) int { return c.Common.Threads })
	assert.Equal(t, 8, value)
}

func TestGetIntValue_DefaultPriority(t *testing.T) {
	// Reset global config
	globalConfig = nil

	cmd := &cobra.Command{}
	cmd.Flags().Int("threads", 4, "Threads")

	// No config, no flag set, should use default
	value := GetIntValue(cmd, "threads", func(c *Config) int {
		if c == nil {
			return 4
		}
		return c.Common.Threads
	})
	assert.Equal(t, 4, value)
}

func TestGetStringSliceValue_FlagPriority(t *testing.T) {
	// Reset global config
	globalConfig = &Config{
		Common: CommonConfig{
			ConfidenceFilter: []string{"high", "medium"},
		},
	}
	defer func() { globalConfig = nil }()

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("confidence", []string{}, "Confidence filter")

	// Set flag explicitly
	err := cmd.Flags().Set("confidence", "low,high")
	assert.NoError(t, err)

	// Flag should take priority over config
	value := GetStringSliceValue(cmd, "confidence", func(c *Config) []string { return c.Common.ConfidenceFilter })
	assert.Equal(t, []string{"low", "high"}, value)
}

func TestGetStringSliceValue_ConfigPriority(t *testing.T) {
	// Reset global config
	globalConfig = &Config{
		Common: CommonConfig{
			ConfidenceFilter: []string{"high", "medium"},
		},
	}
	defer func() { globalConfig = nil }()

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("confidence", []string{}, "Confidence filter")

	// Don't set flag, should use config
	value := GetStringSliceValue(cmd, "confidence", func(c *Config) []string { return c.Common.ConfidenceFilter })
	assert.Equal(t, []string{"high", "medium"}, value)
}

func TestGetStringSliceValue_DefaultPriority(t *testing.T) {
	// Reset global config
	globalConfig = nil

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("confidence", []string{}, "Confidence filter")

	// No config, no flag set, should use default
	value := GetStringSliceValue(cmd, "confidence", func(c *Config) []string {
		if c == nil {
			return []string{}
		}
		return c.Common.ConfidenceFilter
	})
	assert.Equal(t, []string{}, value)
}
