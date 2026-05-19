package vuln

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgvuln "github.com/CompassSecurity/pipeleek/pkg/gitlab/vuln"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url":   "gitlab.url",
	"token": "gitlab.token",
}

func NewVulnCmd() *cobra.Command {
	vulnCmd := &cobra.Command{
		Use:     "vuln",
		Short:   "Check if the installed GitLab version is vulnerable",
		Long:    "Check the installed GitLab instance version against the NIST vulnerability database to see if it is affected by any vulnerabilities.",
		Example: `pipeleek gl vuln --token glpat-xxxxxxxxxxx --url https://gitlab.mydomain.com`,
		Run:     CheckVulns,
	}
	vulnCmd.Flags().StringP("url", "g", "", "GitLab instance URL")
	vulnCmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return vulnCmd
}

func CheckVulns(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("gitlab.token"), "GitLab API Token") }).
		MustBind()

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")

	pkgvuln.RunCheckVulns(gitlabUrl, gitlabApiToken)
}
