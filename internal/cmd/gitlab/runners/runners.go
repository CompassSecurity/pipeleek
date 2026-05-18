package runners

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/runners/exploit"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/runners/list"
	"github.com/spf13/cobra"
)

var (
	gitlabApiToken string
	gitlabUrl      string
)

func NewRunnersRootCmd() *cobra.Command {
	runnersCmd := &cobra.Command{
		Use:   "runners",
		Short: "runner related commands",
		Long:  "Commands to enumerate and exploit GitLab runners.",
	}

	runnersCmd.PersistentFlags().StringVarP(&gitlabUrl, "url", "g", "", "GitLab instance URL")
	runnersCmd.PersistentFlags().StringVarP(&gitlabApiToken, "token", "t", "", "GitLab API Token")

	runnersCmd.AddCommand(list.NewRunnersListCmd())
	runnersCmd.AddCommand(exploit.NewRunnersExploitCmd())

	return runnersCmd
}
