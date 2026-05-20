package devops

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/devops/scan"
	"github.com/spf13/cobra"
)

var (
	devopsApiToken string
	devopsUrl      string
)

func NewAzureDevOpsRootCmd() *cobra.Command {
	dvoCmd := &cobra.Command{
		Use:     "ad [command]",
		Short:   "Azure DevOps related commands",
		GroupID: "AzureDevOps",
	}

	dvoCmd.AddCommand(scan.NewScanCmd())

	dvoCmd.PersistentFlags().StringVarP(&devopsUrl, "url", "u", "https://dev.azure.com", "Azure DevOps instance URL")
	dvoCmd.PersistentFlags().StringVarP(&devopsApiToken, "token", "t", "", "Azure DevOps API Token")

	return dvoCmd
}
