package whoami

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgwhoami "github.com/CompassSecurity/pipeleek/pkg/gitlab/whoami"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url":   "gitlab.url",
	"token": "gitlab.token",
}

func NewWhoAmICmd() *cobra.Command {
	whoAmICmd := &cobra.Command{
		Use:     "whoami",
		Short:   "Display current GitLab user and token details",
		Long:    "Fetch and display details about the currently authenticated GitLab user and the current personal access token.",
		Example: `pipeleek gl whoami --token glpat-xxxxxxxxxxx --url https://gitlab.mydomain.com`,
		Run:     WhoAmI,
	}

	whoAmICmd.Flags().StringP("url", "u", "", "GitLab instance URL")
	whoAmICmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return whoAmICmd
}

func WhoAmI(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("gitlab.token"), "GitLab API Token") }).
		MustBind()

	gitlabURL := config.GetString("gitlab.url")
	gitlabAPIToken := config.GetString("gitlab.token")

	pkgwhoami.RunWhoAmI(gitlabURL, gitlabAPIToken)
}
