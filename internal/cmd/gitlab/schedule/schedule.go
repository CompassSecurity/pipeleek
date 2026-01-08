package schedule

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgschedule "github.com/CompassSecurity/pipeleek/pkg/gitlab/schedule"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewScheduleCmd() *cobra.Command {
	scheduleCmd := &cobra.Command{
		Use:     "schedule",
		Short:   "Enumerate scheduled pipelines and dump their variables",
		Long:    "Fetch and print all scheduled pipelines and their variables for projects your token has access to.",
		Example: `pipeleek gl schedule --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com`,
		Run:     FetchSchedules,
	}
	scheduleCmd.Flags().StringP("gitlab", "g", "", "GitLab instance URL")
	scheduleCmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return scheduleCmd
}

func FetchSchedules(cmd *cobra.Command, args []string) {
	if err := config.AutoBindFlags(cmd, map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
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

	pkgschedule.RunFetchSchedules(gitlabUrl, gitlabApiToken)
}
