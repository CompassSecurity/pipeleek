package config

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// CommandSetup provides a simplified interface for binding flags and validating command configuration.
// It eliminates repetitive boilerplate across all command Run functions.
type CommandSetup struct {
	cmd          *cobra.Command
	flagBindings map[string]string
	requiredKeys []string
	validators   []func() error
}

// NewCommandSetup creates a new CommandSetup helper for a command.
// This should be called at the start of each command's Run function.
func NewCommandSetup(cmd *cobra.Command) *CommandSetup {
	return &CommandSetup{
		cmd:          cmd,
		flagBindings: make(map[string]string),
		requiredKeys: []string{},
		validators:   []func() error{},
	}
}

// WithAutoBindings automatically generates flag bindings from Cobra flag definitions.
// It derives viper keys from flag names, with optional overrides for specific flags.
// Example: flag "max-artifact-size" -> key "common.max_artifact_size" (or override with map)
func (cs *CommandSetup) WithAutoBindings(overrides map[string]string) *CommandSetup {
	cs.cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}

		if override, ok := overrides[flag.Name]; ok {
			cs.flagBindings[flag.Name] = override
		} else {
			// Auto-derive viper key: replace hyphens with underscores and prefix with "common."
			cs.flagBindings[flag.Name] = "common." + strings.ReplaceAll(flag.Name, "-", "_")
		}
	})
	return cs
}

// WithFlagBindings sets explicit flag-to-config-key mappings, replacing any auto-derived bindings.
func (cs *CommandSetup) WithFlagBindings(bindings map[string]string) *CommandSetup {
	cs.flagBindings = bindings
	return cs
}

// RequireKeys marks configuration keys as required; if missing after binding, Bind() will fail.
func (cs *CommandSetup) RequireKeys(keys ...string) *CommandSetup {
	cs.requiredKeys = append(cs.requiredKeys, keys...)
	return cs
}

// AddValidator adds a validation function to run after binding. Useful for chaining
// ValidateURL, ValidateToken, etc. without if-else verbosity.
func (cs *CommandSetup) AddValidator(fn func() error) *CommandSetup {
	cs.validators = append(cs.validators, fn)
	return cs
}

// Bind performs all setup: flag binding, required key validation, and custom validators.
// Returns early on first error.
func (cs *CommandSetup) Bind() error {
	if len(cs.flagBindings) > 0 {
		if err := cs.bindFlags(); err != nil {
			return fmt.Errorf("failed to bind command flags: %w", err)
		}
	}

	if len(cs.requiredKeys) > 0 {
		if err := RequireConfigKeys(cs.requiredKeys...); err != nil {
			return err
		}
	}

	for _, validate := range cs.validators {
		if err := validate(); err != nil {
			return err
		}
	}

	return nil
}

func (cs *CommandSetup) bindFlags() error {
	v := GetViper()

	for flagName, viperKey := range cs.flagBindings {
		flag := cs.cmd.Flags().Lookup(flagName)
		if flag == nil {
			flag = cs.cmd.PersistentFlags().Lookup(flagName)
		}
		if flag == nil {
			flag = cs.cmd.InheritedFlags().Lookup(flagName)
		}
		if flag == nil {
			continue
		}

		if err := v.BindPFlag(viperKey, flag); err != nil {
			return fmt.Errorf("failed to bind flag %s to key %s: %w", flagName, viperKey, err)
		}
	}

	return nil
}

// MustBind is like Bind but logs fatal on error. Use this for commands where failure
// should immediately exit the program.
func (cs *CommandSetup) MustBind() {
	if err := cs.Bind(); err != nil {
		log.Fatal().Err(err).Msg(err.Error())
	}
}

// BindingsFromFlags generates a minimal flagBindings map based on actual flag definitions.
// This is a utility for commands that want to automatically derive keys from flag names.
// It uses the convention: flag "foo-bar" -> "platform.command.foo_bar"
func BindingsFromFlags(cmd *cobra.Command, platformKey string, commandKey string, overrides map[string]string) map[string]string {
	bindings := make(map[string]string)

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}

		if override, ok := overrides[flag.Name]; ok {
			bindings[flag.Name] = override
			return
		}

		normalized := normalizeFlagKey(flag.Name)
		if commandKey != "" {
			bindings[flag.Name] = platformKey + "." + commandKey + "." + normalized
		} else {
			bindings[flag.Name] = platformKey + "." + normalized
		}
	})

	return bindings
}

// ParseBool is a convenience for reading boolean config values with a fallback default.
func ParseBool(key string, defaultValue bool) bool {
	val := GetString(key)
	if val == "" {
		return defaultValue
	}
	return strings.EqualFold(val, "true") || strings.EqualFold(val, "1") || strings.EqualFold(val, "yes")
}
