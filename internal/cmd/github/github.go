package github

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/container"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/ghtoken"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/scan"
	"github.com/spf13/cobra"
)

var (
	githubApiToken string
	githubUrl      string
)

func NewGitHubRootCmd() *cobra.Command {
	ghCmd := &cobra.Command{
		Use:     "gh [command]",
		Short:   "GitHub related commands",
		GroupID: "GitHub",
	}

	ghCmd.AddCommand(scan.NewScanCmd())
	ghCmd.AddCommand(renovate.NewRenovateRootCmd())
	ghCmd.AddCommand(container.NewContainerScanCmd())
	ghCmd.AddCommand(ghtoken.NewGhTokenRootCmd())

	ghCmd.PersistentFlags().StringVarP(&githubUrl, "url", "g", "https://api.github.com", "GitHub instance URL")
	ghCmd.PersistentFlags().StringVarP(&githubApiToken, "token", "t", "", "GitHub API Token")

	return ghCmd
}
