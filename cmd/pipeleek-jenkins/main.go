package main

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/common"
	"github.com/CompassSecurity/pipeleek/internal/cmd/jenkins"
	"github.com/spf13/cobra"
)

func main() {
	common.Run(newRootCmd())
}

func newRootCmd() *cobra.Command {
	jenkinsCmd := jenkins.NewJenkinsRootCmd()
	jenkinsCmd.Use = "pipeleek-jenkins"
	jenkinsCmd.Short = "Scan Jenkins logs and artifacts for secrets"
	jenkinsCmd.Long = `Pipeleek-Jenkins scans Jenkins logs and artifacts to detect leaked secrets and pivot from them.`
	jenkinsCmd.Version = common.Version
	jenkinsCmd.GroupID = ""

	common.SetupPersistentPreRun(jenkinsCmd)
	common.AddCommonFlags(jenkinsCmd)

	jenkinsCmd.SetVersionTemplate(`{{.Version}}
`)

	return jenkinsCmd
}
