package vuln

import (
	pkgvuln "github.com/CompassSecurity/pipeleek/pkg/gitea/vuln"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	giteaApiToken string
	giteaUrl      string
)

func NewVulnCmd() *cobra.Command {
	vulnCmd := &cobra.Command{
		Use:     "vuln",
		Short:   "Check if the installed Gitea version is vulnerable",
		Long:    "Check the installed Gitea instance version against the NIST vulnerability database to see if it is affected by any vulnerabilities.",
		Example: `pipeleek gitea vuln --token xxxxx --gitea https://gitea.mydomain.com`,
		Run:     CheckVulns,
	}
	vulnCmd.Flags().StringVarP(&giteaUrl, "gitea", "g", "", "Gitea instance URL")
	err := vulnCmd.MarkFlagRequired("gitea")
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Unable to require gitea flag")
	}

	vulnCmd.Flags().StringVarP(&giteaApiToken, "token", "t", "", "Gitea API Token")
	err = vulnCmd.MarkFlagRequired("token")
	if err != nil {
		log.Fatal().Msg("Unable to require token flag")
	}
	vulnCmd.MarkFlagsRequiredTogether("gitea", "token")

	return vulnCmd
}

func CheckVulns(cmd *cobra.Command, args []string) {
	pkgvuln.RunCheckVulns(giteaUrl, giteaApiToken)
}
