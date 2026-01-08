package gitea

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitea/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitea/scan"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitea/secrets"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitea/variables"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitea/vuln"
	"github.com/spf13/cobra"
)

var (
	giteaApiToken string
	giteaUrl      string
)

func NewGiteaRootCmd() *cobra.Command {
	giteaCmd := &cobra.Command{
		Use:     "gitea [command]",
		Short:   "Gitea related commands",
		Long:    "Commands to enumerate and exploit Gitea instances.",
		GroupID: "Gitea",
	}

	giteaCmd.AddCommand(enum.NewEnumCmd())
	giteaCmd.AddCommand(scan.NewScanCmd())
	giteaCmd.AddCommand(secrets.NewSecretsCommand())
	giteaCmd.AddCommand(variables.NewVariablesCommand())
	giteaCmd.AddCommand(vuln.NewVulnCmd())

	giteaCmd.PersistentFlags().StringVarP(&giteaUrl, "gitea", "g", "", "Gitea instance URL")
	giteaCmd.PersistentFlags().StringVarP(&giteaApiToken, "token", "t", "", "Gitea API Token")

	return giteaCmd
}
