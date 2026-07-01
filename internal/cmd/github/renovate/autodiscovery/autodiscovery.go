package autodiscovery

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/github/renovate/autodiscovery"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url":       "github.url",
	"token":     "github.token",
	"repo-name": "github.renovate.autodiscovery.repo_name",
	"username":  "github.renovate.autodiscovery.username",
}

func RunAutodiscovery(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("github.token").
		MustBind()

	githubURL := config.GetString("github.url")
	githubAPIToken := config.GetString("github.token")
	repoName := config.GetString("github.renovate.autodiscovery.repo_name")
	username := config.GetString("github.renovate.autodiscovery.username")

	client := pkgscan.SetupClient(githubAPIToken, githubURL)
	pkgrenovate.RunGenerate(client, repoName, username)
}

func NewAutodiscoveryCmd() *cobra.Command {
	autodiscoveryCmd := &cobra.Command{
		Use:   "autodiscovery",
		Short: "Create a PoC for Renovate Autodiscovery misconfigurations exploitation",
		Long:  "Create a repository with a Renovate Bot configuration that will be picked up by an existing Renovate Bot user. The Renovate Bot will execute the malicious Maven wrapper script during dependency updates, which you can customize in exploit.sh. Note: On GitHub, the bot/user account must proactively accept the invite.",
		Example: `
# Create a repository and invite the victim Renovate Bot user to it. Uses the Maven wrapper to execute arbitrary code during dependency updates.
pipeleek gh renovate autodiscovery --token ghp_xxxxx --url https://api.github.com --repo-name my-exploit-repo --username renovate-bot-user
		`,
		Run: RunAutodiscovery,
	}
	var repoName, username string
	autodiscoveryCmd.Flags().StringVarP(&repoName, "repo-name", "r", "", "The name for the created repository")
	autodiscoveryCmd.Flags().StringVarP(&username, "username", "n", "", "The username of the victim Renovate Bot user to invite")

	return autodiscoveryCmd
}
