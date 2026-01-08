package github

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/scan"
	"github.com/spf13/cobra"
)

func NewGitHubRootCmd() *cobra.Command {
	ghCmd := &cobra.Command{
		Use:     "gh [command]",
		Short:   "GitHub related commands",
		GroupID: "GitHub",
	}

	ghCmd.AddCommand(scan.NewScanCmd())
	ghCmd.AddCommand(renovate.NewRenovateRootCmd())

	return ghCmd
}
