package jenkins

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/jenkins/scan"
	"github.com/spf13/cobra"
)

func NewJenkinsRootCmd() *cobra.Command {
	jenkinsCmd := &cobra.Command{
		Use:     "jenkins [command]",
		Short:   "Jenkins related commands",
		GroupID: "Jenkins",
	}

	jenkinsCmd.AddCommand(scan.NewScanCmd())

	return jenkinsCmd
}
