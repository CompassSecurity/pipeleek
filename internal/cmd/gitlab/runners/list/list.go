package list

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrunners "github.com/CompassSecurity/pipeleek/pkg/gitlab/runners/list"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewRunnersListCmd() *cobra.Command {
	runnersCmd := &cobra.Command{
		Use:     "list",
		Short:   "List available runners",
		Long:    "List all available runners for projects and groups your token has access to.",
		Example: `pipeleek gl runners list --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.BindCommandFlags(cmd, "gitlab.runners.list", map[string]string{
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

			pkgrunners.ListAllAvailableRunners(gitlabUrl, gitlabApiToken)
			log.Info().Msg("Done, Bye Bye 🏳️‍🌈🔥")
		},
	}

	return runnersCmd
}
