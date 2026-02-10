package autodiscovery

import (
	"github.com/rs/zerolog/log"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/autodiscovery"
	"github.com/spf13/cobra"
)

var (
	autodiscoveryRepoName string
	autodiscoveryUsername string
	autodiscoveryAddCICD  bool
)

func NewAutodiscoveryCmd() *cobra.Command {
	autodiscoveryCmd := &cobra.Command{
		Use:   "autodiscovery",
		Short: "Create a PoC for Renovate Autodiscovery misconfigurations exploitation",
		Long:  "Create a project with a Renovate Bot configuration that will be picked up by an existing Renovate Bot user. The Renovate Bot will execute the malicious Gradle wrapper script during dependency updates, which you can customize in exploit.sh.",
		Example: `
# Create a project and invite the victim Renovate Bot user to it. Uses Gradle wrapper to execute arbitrary code during dependency updates.
pipeleek gl renovate autodiscovery --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com --repo-name my-exploit-repo --username renovate-bot-user

# Create a project with a CI/CD pipeline for local testing (requires setting RENOVATE_TOKEN as CI/CD variable)
pipeleek gl renovate autodiscovery --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com --repo-name my-exploit-repo --add-renovate-cicd-for-debugging
    `,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"gitlab":                          "gitlab.url",
				"token":                           "gitlab.token",
				"repo-name":                       "gitlab.renovate.autodiscovery.repo_name",
				"username":                        "gitlab.renovate.autodiscovery.username",
				"add-renovate-cicd-for-debugging": "gitlab.renovate.autodiscovery.add_renovate_cicd_for_debugging",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			if err := config.RequireConfigKeys("gitlab.url", "gitlab.token", "gitlab.renovate.autodiscovery.repo_name"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")
			autodiscoveryRepoName = config.GetString("gitlab.renovate.autodiscovery.repo_name")
			autodiscoveryUsername = config.GetString("gitlab.renovate.autodiscovery.username")
			autodiscoveryAddCICD = config.GetBool("gitlab.renovate.autodiscovery.add_renovate_cicd_for_debugging")
			pkgrenovate.RunGenerate(gitlabUrl, gitlabApiToken, autodiscoveryRepoName, autodiscoveryUsername, autodiscoveryAddCICD)
		},
	}
	autodiscoveryCmd.Flags().StringVarP(&autodiscoveryRepoName, "repo-name", "r", "", "The name for the created repository")
	autodiscoveryCmd.Flags().StringVarP(&autodiscoveryUsername, "username", "u", "", "The username of the victim Renovate Bot user to invite")
	autodiscoveryCmd.Flags().BoolVar(&autodiscoveryAddCICD, "add-renovate-cicd-for-debugging", false, "Creates a .gitlab-ci.yml file in the repo that runs Renovate Bot for local testing")

	return autodiscoveryCmd
}
