package container

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/container/artipacked"
	"github.com/spf13/cobra"
)

func NewContainerScanCmd() *cobra.Command {
	containerCmd := &cobra.Command{
		Use:   "container",
		Short: "Container related commands",
		Long:  "Commands to audit container handling and misconfigurations",
	}

	containerCmd.AddCommand(artipacked.NewArtipackedCmd())

	return containerCmd
}
