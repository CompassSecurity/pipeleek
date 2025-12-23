package renovate

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/autodiscovery"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/privesc"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	gitlabApiToken string
	gitlabUrl      string
)

func NewRenovateRootCmd() *cobra.Command {
	renovateCmd := &cobra.Command{
		Use:   "renovate",
		Short: "Renovate related commands",
		Long:  "Commands to enumerate and exploit GitLab Renovate bot configurations.",
	}

	renovateCmd.PersistentFlags().StringVar(&gitlabUrl, "gitlab", "", "GitLab instance URL")
	renovateCmd.PersistentFlags().StringVar(&gitlabApiToken, "token", "", "GitLab API Token")

	renovateCmd.AddCommand(enum.NewEnumCmd())
	renovateCmd.AddCommand(autodiscovery.NewAutodiscoveryCmd())
	renovateCmd.AddCommand(privesc.NewPrivescCmd())

	renovateCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if err := config.BindCommandFlags(cmd, "gitlab.renovate", map[string]string{
			"gitlab": "gitlab.url",
			"token":  "gitlab.token",
		}); err != nil {
			log.Fatal().Err(err).Msg("Failed to bind flags")
		}

		if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
			log.Fatal().Err(err).Msg("Missing required configuration")
		}

		gitlabUrl = config.GetString("gitlab.url")
		gitlabApiToken = config.GetString("gitlab.token")

		if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
			log.Fatal().Err(err).Msg("Invalid GitLab URL")
		}
		if err := config.ValidateToken(gitlabApiToken, "GitLab API Token"); err != nil {
			log.Fatal().Err(err).Msg("Invalid GitLab API Token")
		}
	}

	return renovateCmd
}
