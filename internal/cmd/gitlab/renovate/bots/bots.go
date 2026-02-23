package bots

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgbots "github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/bots"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	searchTerm string
)

func NewBotsCmd() *cobra.Command {
	botsCmd := &cobra.Command{
		Use:   "bots",
		Short: "Enumerate potential Renovate bot user accounts",
		Long:  "Search GitLab users by term, inspect their profile visibility and activity, and highlight potential Renovate bot accounts.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"gitlab": "gitlab.url",
				"token":  "gitlab.token",
				"term":   "gitlab.renovate.bots.term",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			if err := config.RequireConfigKeys("gitlab.url", "gitlab.token", "gitlab.renovate.bots.term"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")
			searchTerm = config.GetString("gitlab.renovate.bots.term")

			pkgbots.RunEnumerateBots(gitlabUrl, gitlabApiToken, searchTerm)
		},
	}

	botsCmd.Flags().StringVar(&searchTerm, "term", "renovate", "Search term for GitLab users (e.g., renovate, bot)")

	return botsCmd
}
