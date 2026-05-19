package jenkins

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/jenkins/scan"
	"github.com/spf13/cobra"
)

var (
	jenkinsApiToken string
	jenkinsUrl      string
)

func NewJenkinsRootCmd() *cobra.Command {
	jenkinsCmd := &cobra.Command{
		Use:     "jenkins [command]",
		Short:   "Jenkins related commands",
		GroupID: "Jenkins",
	}

	jenkinsCmd.AddCommand(scan.NewScanCmd())

	jenkinsCmd.PersistentFlags().StringVarP(&jenkinsUrl, "url", "j", "", "Jenkins instance URL")
	jenkinsCmd.PersistentFlags().StringVarP(&jenkinsApiToken, "token", "t", "", "Jenkins API Token")

	return jenkinsCmd
}
