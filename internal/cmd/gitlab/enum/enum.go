package enum

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgenum "github.com/CompassSecurity/pipeleek/pkg/gitlab/enum"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func NewEnumCmd() *cobra.Command {
	enumCmd := &cobra.Command{
		Use:     "enum",
		Short:   "Enumerate access rights of a GitLab access token",
		Long:    "Enumerate access rights of a GitLab access token by listing projects, groups and users the token has access to.",
		Example: `pipeleek gl enum --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com --level 20`,
		Run:     Enum,
	}
	enumCmd.Flags().StringP("gitlab", "g", "", "GitLab instance URL")
	enumCmd.Flags().StringP("token", "t", "", "GitLab API Token")
	enumCmd.Flags().Int("level", int(gitlab.GuestPermissions), "Minimum repo access level. See https://docs.gitlab.com/api/access_requests/#valid-access-levels for integer values")

	return enumCmd
}

func Enum(cmd *cobra.Command, args []string) {
	if err := config.BindCommandFlags(cmd, "gitlab.enum", map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind flags")
	}

	if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
		log.Fatal().Err(err).Msg("Missing required configuration")
	}

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")
	minAccessLevel := config.GetInt("gitlab.enum.level")

	if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab URL")
	}
	if err := config.ValidateToken(gitlabApiToken, "GitLab API Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab API Token")
	}

	pkgenum.RunEnum(gitlabUrl, gitlabApiToken, minAccessLevel)
}
