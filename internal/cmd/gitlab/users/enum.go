package users

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgusers "github.com/CompassSecurity/pipeleek/pkg/gitlab/users"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewEnumCmd() *cobra.Command {
	enumCmd := &cobra.Command{
		Use:     "enum",
		Short:   "Enumerate GitLab users",
		Long:    "Enumerate GitLab users visible via the GitLab users API.",
		Example: `pipeleek gl users enum --gitlab https://gitlab.example.com --token glpat-xxxxxxxxxxx`,
		Run:     Enum,
	}
	enumCmd.Flags().StringP("gitlab", "g", "", "GitLab instance URL")
	enumCmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return enumCmd
}

func Enum(cmd *cobra.Command, args []string) {
	if err := config.AutoBindFlags(cmd, map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
	}

	if err := config.RequireConfigKeys("gitlab.url"); err != nil {
		log.Fatal().Err(err).Msg("required configuration missing")
	}

	gitlabURL := config.GetString("gitlab.url")
	gitlabAPIToken := config.GetString("gitlab.token")

	if err := config.ValidateURL(gitlabURL, "GitLab URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab URL")
	}
	if gitlabAPIToken != "" {
		if err := config.ValidateToken(gitlabAPIToken, "GitLab API Token"); err != nil {
			log.Fatal().Err(err).Msg("Invalid GitLab API Token")
		}
	}

	pkgusers.RunEnum(gitlabURL, gitlabAPIToken)
}
