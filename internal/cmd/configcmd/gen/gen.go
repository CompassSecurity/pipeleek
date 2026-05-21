package gen

import (
	"fmt"
	"github.com/rs/zerolog/log"

	"github.com/CompassSecurity/pipeleek/internal/cmd/configcmd/common"
	configgen "github.com/CompassSecurity/pipeleek/pkg/config/gen"
	"github.com/spf13/cobra"
)

func NewGenCmd() *cobra.Command {
	var outputFile string

	genCmd := &cobra.Command{
		Use:          "gen",
		Short:        "Generate an example pipeleek configuration file",
		SilenceUsage: true,
		Long: `Generate an example pipeleek.yaml configuration file that documents all
available settings, their default values, corresponding CLI flags, and
environment variable names.

The generated file can be used as a starting point for your own configuration.
Copy it to one of the standard locations and edit as needed:
  - ~/.config/pipeleek/pipeleek.yaml (recommended)
  - ~/pipeleek.yaml
  - ./pipeleek.yaml`,
		Example: `
# Print example config to stdout
pipeleek config gen

# Write example config to a file
pipeleek config gen --output pipeleek.yaml

# Generate and write to the standard config location
pipeleek config gen --output ~/.config/pipeleek/pipeleek.yaml
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			content := configgen.GenerateExampleConfig(cmd.Root())
			if content == "" {
				return common.WrapError("gen", "generate example config", fmt.Errorf("generator returned empty output"))
			}

			if outputFile != "" {
				if err := writeFile(outputFile, content); err != nil {
					return common.WrapError("gen", "write output file", err)
				}
				logger := log.Output(cmd.OutOrStdout())
				logger.Info().Msgf("Example configuration written to %s", outputFile)
				return nil
			}

			fmt.Fprint(cmd.OutOrStdout(), content)
			return nil
		},
	}

	genCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")

	return genCmd
}
