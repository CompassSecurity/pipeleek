package renovate

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate/autodiscovery"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate/lab"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate/privesc"
	"github.com/spf13/cobra"
)

var (
	githubApiToken string
	githubUrl      string
)

func NewRenovateRootCmd() *cobra.Command {
	renovateCmd := &cobra.Command{
		Use:   "renovate",
		Short: "Renovate related commands",
		Long:  "Commands to enumerate and exploit GitHub Renovate bot configurations.",
	}

	renovateCmd.PersistentFlags().StringVarP(&githubUrl, "github", "g", "https://api.github.com", "GitHub API base URL")
	renovateCmd.PersistentFlags().StringVarP(&githubApiToken, "token", "t", "", "GitHub Personal Access Token")

	renovateCmd.AddCommand(enum.NewEnumCmd())
	renovateCmd.AddCommand(autodiscovery.NewAutodiscoveryCmd())
	renovateCmd.AddCommand(lab.NewLabCmd())
	renovateCmd.AddCommand(privesc.NewPrivescCmd())

	return renovateCmd
}
