package bots

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgbots "github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/bots"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url":   "gitlab.url",
	"token": "gitlab.token",
	"term":  "gitlab.renovate.bots.term",
}

// RunBots handles the bots command execution
func RunBots(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token", "gitlab.renovate.bots.term").
		MustBind()

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")
	searchTerm := config.GetString("gitlab.renovate.bots.term")

	pkgbots.RunEnumerateBots(gitlabUrl, gitlabApiToken, searchTerm)
}

func NewBotsCmd() *cobra.Command {
	botsCmd := &cobra.Command{
		Use:   "bots",
		Short: "Enumerate potential Renovate bot user accounts",
		Long:  "Search GitLab users by term, inspect their profile visibility and activity, and highlight potential Renovate bot accounts.",
		Run:   RunBots,
	}

	botsCmd.Flags().String("term", "renovate", "Search term for GitLab users (e.g., renovate, bot)")

	return botsCmd
}
