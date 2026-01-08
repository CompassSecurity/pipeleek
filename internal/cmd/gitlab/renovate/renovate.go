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

	// Bind config before executing subcommands; keep root's PersistentPreRun
	// for logger setup by using PreRun (not PersistentPreRun)
	renovateCmd.PreRun = func(cmd *cobra.Command, args []string) {
		// Bind flags to config keys
		if err := config.BindCommandFlags(cmd, "gitlab.renovate", map[string]string{
			"gitlab": "gitlab.url",
			"token":  "gitlab.token",
		}); err != nil {
			log.Fatal().Err(err).Msg("Failed to bind flags to config")
		}

		// Get values from config (supports CLI flags, config file, and env vars)
		gitlabUrl = config.GetString("gitlab.url")
		gitlabApiToken = config.GetString("gitlab.token")

		// Validate required values
		if gitlabUrl == "" {
			log.Fatal().Msg("GitLab URL is required (use --gitlab flag, config file, or PIPELEEK_GITLAB_URL env var)")
		}
		if gitlabApiToken == "" {
			log.Fatal().Msg("GitLab token is required (use --token flag, config file, or PIPELEEK_GITLAB_TOKEN env var)")
		}
	}

	renovateCmd.PersistentFlags().StringVarP(&gitlabUrl, "gitlab", "g", "", "GitLab instance URL")
	renovateCmd.PersistentFlags().StringVarP(&gitlabApiToken, "token", "t", "", "GitLab API Token")

	renovateCmd.AddCommand(enum.NewEnumCmd())
	renovateCmd.AddCommand(autodiscovery.NewAutodiscoveryCmd())
	renovateCmd.AddCommand(privesc.NewPrivescCmd())

	return renovateCmd
}
