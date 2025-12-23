package renovate

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/autodiscovery"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/privesc"
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

	renovateCmd.PersistentFlags().StringVarP(&gitlabUrl, "gitlab", "g", "", "GitLab instance URL")
	err := renovateCmd.MarkPersistentFlagRequired("gitlab")
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Unable to require gitlab flag")
	}

	renovateCmd.PersistentFlags().StringVarP(&gitlabApiToken, "token", "t", "", "GitLab API Token")
	err = renovateCmd.MarkPersistentFlagRequired("token")
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Unable to require token flag")
	}
	renovateCmd.MarkFlagsRequiredTogether("gitlab", "token")

	renovateCmd.AddCommand(enum.NewEnumCmd())
	renovateCmd.AddCommand(autodiscovery.NewAutodiscoveryCmd())
	renovateCmd.AddCommand(privesc.NewPrivescCmd())

	return renovateCmd
}
