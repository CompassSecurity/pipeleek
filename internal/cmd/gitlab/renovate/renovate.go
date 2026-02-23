package renovate

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/autodiscovery"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/bots"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate/privesc"
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
	renovateCmd.PersistentFlags().StringVarP(&gitlabApiToken, "token", "t", "", "GitLab API Token")

	renovateCmd.AddCommand(enum.NewEnumCmd())
	renovateCmd.AddCommand(bots.NewBotsCmd())
	renovateCmd.AddCommand(autodiscovery.NewAutodiscoveryCmd())
	renovateCmd.AddCommand(privesc.NewPrivescCmd())

	return renovateCmd
}
