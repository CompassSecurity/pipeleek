package set

import (
	"fmt"
	"strings"

	"github.com/CompassSecurity/pipeleek/internal/cmd/configcmd/common"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	configgen "github.com/CompassSecurity/pipeleek/pkg/config/gen"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func NewSetCmd() *cobra.Command {
	setCmd := &cobra.Command{
		Use:           "set <key.id> <value>",
		Short:         "Set a configuration value",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `Set a configuration value in the config file by dotted key path.
The value is parsed as YAML, allowing you to set strings, numbers, booleans, arrays, and objects.
Intermediate objects in the key path are created automatically if they don't exist.

Examples of value formats:
  pipeleek config set common.threads 8
  pipeleek config set gitlab.url https://gitlab.example.com
  pipeleek config set common.trufflehog_verification true
  pipeleek config set gitlab.runners.exploit.tags '[docker, linux]'`,
		Example: `
# Set a scalar string
pipeleek config set gitlab.url https://gitlab.example.com

# Set a number
pipeleek config set common.threads 16

# Set a boolean
pipeleek config set common.trufflehog_verification false

# Set an array
pipeleek config set gitlab.runners.exploit.tags '[docker, linux]'

# Set a nested object (advanced)
pipeleek config set gitlab.runners '{exploit: {tags: [docker]}}'`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := common.CanonicalizeKeyPath(args[0])
			valueStr := args[1]
			if err := common.ValidateKeyPath(args[0]); err != nil {
				return common.LogAndWrapError("set", "validate key path", err)
			}
			if !configgen.IsAllowedConfigPath(cmd.Root(), key) {
				return common.LogAndWrapError("set", "validate key path", fmt.Errorf("key %q is not an allowed configuration path", args[0]))
			}

			configPath := common.ResolveWriteConfigPath()

			configData, err := config.LoadConfigFile(configPath)
			if err != nil {
				return common.LogAndWrapError("set", "load config file", err)
			}

			parsedValue, err := parseYAMLValue(valueStr)
			if err != nil {
				return common.LogAndWrapError("set", "parse value", err)
			}

			if err := config.SetByPath(configData, key, parsedValue); err != nil {
				return common.LogAndWrapError("set", "update key", err)
			}

			writePath, err := config.WriteConfigFile(configPath, configData)
			if err != nil {
				return common.LogAndWrapError("set", "write config file", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Configuration updated: %s = %v (written to %s)\n", key, parsedValue, writePath)
			return nil
		},
	}

	return setCmd
}

// parseYAMLValue parses a CLI string value as YAML to infer types.
// If the string looks like YAML syntax (starts with {, [, true, false, or is a number),
// it's parsed as YAML. Otherwise, it's treated as a quoted string.
func parseYAMLValue(valueStr string) (interface{}, error) {
	if looksLikeYAML(valueStr) {
		var result interface{}
		if err := yaml.Unmarshal([]byte(valueStr), &result); err != nil {
			return nil, fmt.Errorf("invalid YAML value %q: %w (tip: quote plain strings, e.g. \"%s\")", valueStr, err, valueStr)
		}
		return result, nil
	}

	if valueStr == "true" {
		return true, nil
	}
	if valueStr == "false" {
		return false, nil
	}

	var numVal interface{}
	if err := yaml.Unmarshal([]byte(valueStr), &numVal); err == nil {
		switch numVal.(type) {
		case int, int64, float64:
			return numVal, nil
		}
	}

	return valueStr, nil
}

// looksLikeYAML checks if a string looks like it should be parsed as YAML
func looksLikeYAML(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return false
	}

	first := s[0]
	if first == '[' || first == '{' || first == '|' || first == '>' || first == '-' {
		return true
	}

	if s == "null" || s == "~" {
		return true
	}

	return false
}
