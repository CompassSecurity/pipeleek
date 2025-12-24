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

	runnersCmd.PersistentFlags().StringVar(&gitlabUrl, "gitlab", "", "GitLab instance URL")
	runnersCmd.PersistentFlags().StringVar(&gitlabApiToken, "token", "", "GitLab API Token")

	runnersCmd.AddCommand(list.NewRunnersListCmd())
	runnersCmd.AddCommand(exploit.NewRunnersExploitCmd())

	return runnersCmd
}
