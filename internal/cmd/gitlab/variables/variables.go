package variables

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgvariables "github.com/CompassSecurity/pipeleek/pkg/gitlab/variables"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"gitlab": "gitlab.url",
	"token":  "gitlab.token",
}

func NewVariablesCmd() *cobra.Command {
	variablesCmd := &cobra.Command{
		Use:     "variables",
		Short:   "Print configured CI/CD variables",
		Long:    "Fetch and print all configured CI/CD variables for projects, groups and instance (if admin) your token has access to.",
		Example: `pipeleek gl variables --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com`,
		Run:     FetchVariables,
	}
	variablesCmd.Flags().StringP("gitlab", "g", "", "GitLab instance URL")
	variablesCmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return variablesCmd
}

func FetchVariables(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("gitlab.token"), "GitLab API Token") }).
		MustBind()

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")

	pkgvariables.RunFetchVariables(gitlabUrl, gitlabApiToken)
}
