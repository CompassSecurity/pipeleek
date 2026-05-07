package common

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/rs/zerolog/log"
)

// WrapError formats all config subcommand errors in a consistent UX-friendly shape.
func WrapError(command string, action string, err error) error {
	if err == nil {
		return nil
	}
	if action == "" {
		return fmt.Errorf("config %s: %w", command, err)
	}
	return fmt.Errorf("config %s: %s: %w", command, action, err)
}

// LogAndWrapError logs an error through zerolog and then wraps it for return.
// This ensures errors go through zerolog's logging infrastructure, preventing terminal state corruption.
func LogAndWrapError(command string, action string, err error) error {
	if err == nil {
		return nil
	}
	// Log the error through zerolog first
	log.Error().Err(err).Str("command", command).Str("action", action).Msg("Command failed")
	// Return the wrapped error
	return WrapError(command, action, err)
}

// ValidateKeyPath validates dotted config keys such as gitlab.token.
func ValidateKeyPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("key path must not be empty")
	}
	if strings.HasPrefix(path, ".") || strings.HasSuffix(path, ".") {
		return fmt.Errorf("invalid key path %q: must not start or end with '.'", path)
	}
	parts := strings.Split(path, ".")
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return fmt.Errorf("invalid key path %q: contains empty path segment", path)
		}
	}
	return nil
}

// ResolveReadConfigPath returns the loaded config path and logs a warning if none is loaded.
func ResolveReadConfigPath() string {
	v := config.GetViper()
	configPath := v.ConfigFileUsed()
	if configPath != "" {
		ext := strings.ToLower(filepath.Ext(configPath))
		if ext == ".yaml" || ext == ".yml" {
			return configPath
		}
		log.Warn().Str("detected_path", configPath).Msg("Ignoring non-YAML config candidate")
		configPath = ""
	}
	if configPath == "" {
		fallback := config.GetEffectiveConfigPath("")
		log.Warn().Str("expected_path", fallback).Msg("No config file found; reading defaults and environment variables")
	}
	return configPath
}

// ResolveWriteConfigPath returns a writable config path and logs user-facing context.
func ResolveWriteConfigPath() string {
	v := config.GetViper()
	configPath := v.ConfigFileUsed()
	if configPath != "" {
		ext := strings.ToLower(filepath.Ext(configPath))
		if ext == ".yaml" || ext == ".yml" {
			return configPath
		}
		log.Warn().Str("detected_path", configPath).Msg("Ignoring non-YAML config candidate")
		configPath = ""
	}
	if configPath == "" {
		configPath = config.GetEffectiveConfigPath("")
		log.Warn().Str("config_path", configPath).Msg("No existing config file found; a new config file will be created")
	}
	return configPath
}
