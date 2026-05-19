package get

import (
	"github.com/rs/zerolog/log"
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
		Use:           "get <key.id>",
		Short:         "Get a configuration value",
		SilenceUsage:  true,
		SilenceErrors: true,
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
					return common.LogAndWrapError("get", "validate key path", err)
				}
				key := common.CanonicalizeKeyPath(args[0])
				if !configgen.IsAllowedReadConfigPath(cmd.Root(), key) {
					return common.LogAndWrapError("get", "validate key path", fmt.Errorf("key %q is not an allowed configuration path", args[0]))
				}
			}

			configPath := common.ResolveReadConfigPath()
			v := config.GetViper()

			configData, err := config.LoadConfigFile(configPath)
			if err != nil {
				return common.LogAndWrapError("get", "load config file", err)
			}

			if len(args) == 0 {
				return printConfigValue(cmd, configData)
			}

			key := common.CanonicalizeKeyPath(args[0])

			value, found := config.GetByPath(configData, key)
			if !found {
				// If not found in file config, try Viper's values (includes defaults and env vars)
				value = v.Get(key)
				if value == nil {
					return common.LogAndWrapError("get", "lookup key", fmt.Errorf("key %q was not found in config file, defaults, or environment", key))
				}
			}

			if err := printConfigValue(cmd, value); err != nil {
				return common.LogAndWrapError("get", "render output", err)
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
		fmt.Fprint(cmd.OutOrStdout(), v)
		if !strings.HasSuffix(v, "\n") {
			fmt.Fprint(cmd.OutOrStdout(), "\n")
		}

	case float64:
		logger := log.Output(cmd.OutOrStdout())
		logger.Info().Msgf("%v", v)

	case bool:
		logger := log.Output(cmd.OutOrStdout())
		logger.Info().Msgf("%v", v)

	case []interface{}:
		out, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal array: %w", err)
		}
		fmt.Fprint(cmd.OutOrStdout(), string(out))

	case []string:
		out, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal list: %w", err)
		}
		fmt.Fprint(cmd.OutOrStdout(), string(out))

	case map[string]interface{}:
		out, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal object: %w", err)
		}
		fmt.Fprint(cmd.OutOrStdout(), string(out))

	case nil:
		fmt.Fprint(cmd.OutOrStdout(), "{}\n")

	default:
		out, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		fmt.Fprint(cmd.OutOrStdout(), string(out))
	}

	return nil
}
