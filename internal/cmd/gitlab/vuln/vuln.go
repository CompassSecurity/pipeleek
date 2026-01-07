package vuln

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgvuln "github.com/CompassSecurity/pipeleek/pkg/gitlab/vuln"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewVulnCmd() *cobra.Command {
	vulnCmd := &cobra.Command{
		Use:     "vuln",
		Short:   "Check if the installed GitLab version is vulnerable",
		Long:    "Check the installed GitLab instance version against the NIST vulnerability database to see if it is affected by any vulnerabilities.",
		Example: `pipeleek gl vuln --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com`,
		Run:     CheckVulns,
	}
	vulnCmd.Flags().StringP("gitlab", "g", "", "GitLab instance URL")
	vulnCmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return vulnCmd
}

func CheckVulns(cmd *cobra.Command, args []string) {
	if err := config.BindCommandFlags(cmd, "gitlab.vuln", map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind flags")
	}

	if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
		log.Fatal().Err(err).Msg("required configuration missing")
	}

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")

	if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab URL")
	}
	if err := config.ValidateToken(gitlabApiToken, "GitLab API Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab API Token")
	}

	pkgvuln.RunCheckVulns(gitlabUrl, gitlabApiToken)
}
