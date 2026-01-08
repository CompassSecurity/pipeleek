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
		Long:  "Create a repository with a Renovate Bot configuration that will be picked up by an existing Renovate Bot user. The Renovate Bot will execute the malicious Gradle wrapper script during dependency updates, which you can customize in exploit.sh. Note: On GitHub, the bot/user account must proactively accept the invite.",
		Example: `
# Create a repository and invite the victim Renovate Bot user to it. Uses Gradle wrapper to execute arbitrary code during dependency updates.
pipeleek gh renovate autodiscovery --token ghp_xxxxx --github https://api.github.com --repo-name my-exploit-repo --username renovate-bot-user
		`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.BindCommandFlags(cmd, "github.renovate.autodiscovery", nil); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags")
			}

			if !cmd.Flags().Changed("repo-name") {
				autodiscoveryRepoName = config.GetString("github.renovate.autodiscovery.repo_name")
			}
			if !cmd.Flags().Changed("username") {
				autodiscoveryUsername = config.GetString("github.renovate.autodiscovery.username")
			}

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
