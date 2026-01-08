package vuln

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgvuln "github.com/CompassSecurity/pipeleek/pkg/gitea/vuln"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewVulnCmd() *cobra.Command {
	vulnCmd := &cobra.Command{
		Use:     "vuln",
		Short:   "Check if the installed Gitea version is vulnerable",
		Long:    "Check the installed Gitea instance version against the NIST vulnerability database to see if it is affected by any vulnerabilities.",
		Example: `pipeleek gitea vuln --token xxxxx --gitea https://gitea.mydomain.com`,
		Run:     CheckVulns,
	}

	return vulnCmd
}

func CheckVulns(cmd *cobra.Command, args []string) {
	if err := config.AutoBindFlags(cmd, map[string]string{
		"gitea": "gitea.url",
		"token": "gitea.token",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
	}

	if err := config.RequireConfigKeys("gitea.url", "gitea.token"); err != nil {
		log.Fatal().Err(err).Msg("required configuration missing")
	}

	giteaUrl := config.GetString("gitea.url")
	giteaApiToken := config.GetString("gitea.token")

	pkgvuln.RunCheckVulns(giteaUrl, giteaApiToken)
}
