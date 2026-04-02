package main

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/circle"
	"github.com/CompassSecurity/pipeleek/internal/cmd/common"
	"github.com/spf13/cobra"
)

func main() {
	common.Run(newRootCmd())
}

func newRootCmd() *cobra.Command {
	circleCmd := circle.NewCircleRootCmd()
	circleCmd.Use = "pipeleek-circle"
	circleCmd.Short = "Scan CircleCI logs and artifacts for secrets"
	circleCmd.Long = `Pipeleek-Circle scans CircleCI pipelines, logs, test results, and artifacts to detect leaked secrets.`
	circleCmd.Version = common.Version
	circleCmd.GroupID = ""

	common.SetupPersistentPreRun(circleCmd)
	common.AddCommonFlags(circleCmd)

	circleCmd.SetVersionTemplate(`{{.Version}}
`)

	return circleCmd
}
