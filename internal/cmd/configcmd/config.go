package configcmd

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/configcmd/gen"
	getcmd "github.com/CompassSecurity/pipeleek/internal/cmd/configcmd/get"
	setcmd "github.com/CompassSecurity/pipeleek/internal/cmd/configcmd/set"
	"github.com/spf13/cobra"
)

func NewConfigRootCmd() *cobra.Command {
	configCmd := &cobra.Command{
		Use:     "config [command]",
		Short:   "Configuration management commands",
		GroupID: "Config",
		SilenceUsage: true,
	}

	configCmd.AddCommand(gen.NewGenCmd())
	configCmd.AddCommand(getcmd.NewGetCmd())
	configCmd.AddCommand(setcmd.NewSetCmd())

	return configCmd
}
