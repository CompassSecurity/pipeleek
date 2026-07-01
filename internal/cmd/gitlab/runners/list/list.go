package list

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrunners "github.com/CompassSecurity/pipeleek/pkg/gitlab/runners/list"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url": "gitlab.url",
	"token":  "gitlab.token",
}

// RunListRunners handles the list command execution
func RunListRunners(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("gitlab.token"), "GitLab API Token") }).
		MustBind()

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")

	pkgrunners.ListAllAvailableRunners(gitlabUrl, gitlabApiToken)
	log.Info().Msg("Done, Bye Bye 🏳️‍🌈🔥")
}

func NewRunnersListCmd() *cobra.Command {
	runnersCmd := &cobra.Command{
		Use:     "list",
		Short:   "List available runners",
		Long:    "List all available runners for projects and groups your token has access to.",
		Example: `pipeleek gl runners list --token glpat-xxxxxxxxxxx --url https://gitlab.mydomain.com`,
		Run:     RunListRunners,
	}

	return runnersCmd
}
