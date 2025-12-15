package config

import (
	"github.com/spf13/cobra"
)

// GetStringValue retrieves a string value with priority: CLI flag > config file > default.
// If the CLI flag was explicitly set, it takes precedence over the config file.
// Otherwise, it tries to get the value from the config file.
// If neither is set, it returns the default value (current flag value).
// Note: Empty strings in config files are treated as unset and fall back to defaults.
// This is intentional to prevent accidentally overriding defaults with empty values.
func GetStringValue(cmd *cobra.Command, flagName string, configGetter func(*Config) string) string {
	// Check if the flag was explicitly set via CLI
	if cmd.Flags().Changed(flagName) {
		val, _ := cmd.Flags().GetString(flagName)
		return val
	}

	// Try to get value from config file if it was loaded
	// Empty strings are treated as unset to prevent accidental override
	if globalConfig != nil {
		if configValue := configGetter(globalConfig); configValue != "" {
			return configValue
		}
	}

	// Fall back to default (current flag value)
	val, _ := cmd.Flags().GetString(flagName)
	return val
}

// GetBoolValue retrieves a bool value with priority: CLI flag > config file > default.
// For booleans from config files, we cannot easily distinguish between an explicit false
// and a missing value. This function will use the config file value only if a config
// file was actually loaded.
func GetBoolValue(cmd *cobra.Command, flagName string, configGetter func(*Config) bool) bool {
	// Check if the flag was explicitly set via CLI
	if cmd.Flags().Changed(flagName) {
		val, _ := cmd.Flags().GetBool(flagName)
		return val
	}

	// Try to get value from config file if it was loaded
	// Note: We can't distinguish between an explicit false in config vs unset,
	// so we only apply config values when a config was actually loaded
	if globalConfig != nil {
		return configGetter(globalConfig)
	}

	// Fall back to default (current flag value)
	val, _ := cmd.Flags().GetBool(flagName)
	return val
}

// GetIntValue retrieves an int value with priority: CLI flag > config file > default.
// Note: Zero values in config files are treated as unset and fall back to defaults.
// This prevents accidentally setting thread count to 0 which would be invalid.
// To explicitly set a value, use a CLI flag.
func GetIntValue(cmd *cobra.Command, flagName string, configGetter func(*Config) int) int {
	// Check if the flag was explicitly set via CLI
	if cmd.Flags().Changed(flagName) {
		val, _ := cmd.Flags().GetInt(flagName)
		return val
	}

	// Try to get value from config file if it was loaded
	// Zero values are treated as unset to prevent invalid configurations
	if globalConfig != nil {
		if configValue := configGetter(globalConfig); configValue != 0 {
			return configValue
		}
	}

	// Fall back to default (current flag value)
	val, _ := cmd.Flags().GetInt(flagName)
	return val
}

// GetStringSliceValue retrieves a string slice value with priority: CLI flag > config file > default.
// Note: Empty slices in config files are treated as unset and fall back to defaults.
// This is consistent with how Viper handles empty slices. To explicitly disable a filter,
// use a CLI flag with an empty value.
func GetStringSliceValue(cmd *cobra.Command, flagName string, configGetter func(*Config) []string) []string {
	// Check if the flag was explicitly set via CLI
	if cmd.Flags().Changed(flagName) {
		val, _ := cmd.Flags().GetStringSlice(flagName)
		return val
	}

	// Try to get value from config file if it was loaded
	// Empty slices are treated as unset, consistent with Viper behavior
	if globalConfig != nil {
		if configValue := configGetter(globalConfig); len(configValue) > 0 {
			return configValue
		}
	}

	// Fall back to default (current flag value)
	val, _ := cmd.Flags().GetStringSlice(flagName)
	return val
}
