package get

import (
	"fmt"
	"strings"

	"github.com/CompassSecurity/pipeleek/internal/cmd/configcmd/common"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	configgen "github.com/CompassSecurity/pipeleek/pkg/config/gen"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func NewGetCmd() *cobra.Command {
	getCmd := &cobra.Command{
		Use:          "get <key.id>",
		Short:        "Get a configuration value",
		SilenceUsage: true,
		Long: `Get a configuration value from the current config file by dotted key path.
If the key is a leaf value (scalar), it will be printed as-is.
If the key is an object or array, it will be formatted as YAML.
If no key is specified, returns the entire configuration.`,
		Example: `
# Get a scalar value
pipeleek config get gitlab.url

# Get an entire section
pipeleek config get gitlab

# Get a nested value
pipeleek config get gitlab.runners.exploit.tags

# Get the entire configuration
pipeleek config get`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				if err := common.ValidateKeyPath(args[0]); err != nil {
					return common.WrapError("get", "validate key path", err)
				}
				if !configgen.IsAllowedConfigPath(cmd.Root(), args[0]) {
					return common.WrapError("get", "validate key path", fmt.Errorf("key %q is not an allowed configuration path", args[0]))
				}
			}

			   // Resolve config path only after validation passes
			   configPath := common.ResolveReadConfigPath()
			   v := config.GetViper()

			// Load the raw config as a map
			configData, err := config.LoadConfigFile(configPath)
			if err != nil {
				return common.WrapError("get", "load config file", err)
			}

			// If no key specified, print entire config
			if len(args) == 0 {
				return printConfigValue(cmd, configData)
			}

			key := args[0]

			// Get the value by dotted path
			value, found := config.GetByPath(configData, key)
			if !found {
				// If not found in file config, try Viper's values (includes defaults and env vars)
				value = v.Get(key)
				if value == nil {
					return common.WrapError("get", "lookup key", fmt.Errorf("key %q was not found in config file, defaults, or environment", key))
				}
			}

			if err := printConfigValue(cmd, value); err != nil {
				return common.WrapError("get", "render output", err)
			}

			return nil
		},
	}

	return getCmd
}

// printConfigValue prints a config value, formatting objects and arrays as YAML.
func printConfigValue(cmd *cobra.Command, value interface{}) error {
	switch v := value.(type) {
	case string:
		// Leaf string value - print directly
		fmt.Fprint(cmd.OutOrStdout(), v)
		if !strings.HasSuffix(v, "\n") {
			fmt.Fprint(cmd.OutOrStdout(), "\n")
		}

	case float64:
		// Numbers might be returned as float64 from Viper
		fmt.Fprintf(cmd.OutOrStdout(), "%v\n", v)

	case bool:
		fmt.Fprintf(cmd.OutOrStdout(), "%v\n", v)

	case []interface{}:
		// Array - format as YAML
		out, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal array: %w", err)
		}
		fmt.Fprint(cmd.OutOrStdout(), string(out))

	case []string:
		// String slice - format as YAML
		out, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal list: %w", err)
		}
		fmt.Fprint(cmd.OutOrStdout(), string(out))

	case map[string]interface{}:
		// Object - format as YAML with sorted keys
		out, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal object: %w", err)
		}
		fmt.Fprint(cmd.OutOrStdout(), string(out))

	case nil:
		// Return empty object for nil
		fmt.Fprint(cmd.OutOrStdout(), "{}\n")

	default:
		// Fallback: marshal as-is
		out, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		fmt.Fprint(cmd.OutOrStdout(), string(out))
	}

	return nil
}
