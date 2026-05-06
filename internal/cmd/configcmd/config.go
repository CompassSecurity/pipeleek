package configcmd

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/configcmd/gen"
	"github.com/spf13/cobra"
)

func NewConfigRootCmd() *cobra.Command {
	configCmd := &cobra.Command{
		Use:     "config [command]",
		Short:   "Configuration management commands",
		GroupID: "Config",
	}

	configCmd.AddCommand(gen.NewGenCmd())

	return configCmd
}
