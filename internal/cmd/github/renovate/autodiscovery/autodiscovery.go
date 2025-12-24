package autodiscovery

import (
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/github/renovate/autodiscovery"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/spf13/cobra"
)

var (
	autodiscoveryRepoName string
	autodiscoveryUsername string
	autodiscoveryAddWorkflow bool
)

func NewAutodiscoveryCmd() *cobra.Command {
	autodiscoveryCmd := &cobra.Command{
		Use:   "autodiscovery",
		Short: "Create a PoC for Renovate Autodiscovery misconfigurations exploitation",
		Long:  "Create a repository with a Renovate Bot configuration that will be picked up by an existing Renovate Bot user. The Renovate Bot will execute the malicious Gradle wrapper script during dependency updates, which you can customize in exploit.sh.",
		Example: `
# Create a repository and invite the victim Renovate Bot user to it. Uses Gradle wrapper to execute arbitrary code during dependency updates.
pipeleek gh renovate autodiscovery --token ghp_xxxxx --github https://api.github.com --repo-name my-exploit-repo --username renovate-bot-user

# Create a repository with a GitHub Actions workflow for local testing (requires setting RENOVATE_TOKEN as repository secret)
pipeleek gh renovate autodiscovery --token ghp_xxxxx --github https://api.github.com --repo-name my-exploit-repo --add-renovate-workflow-for-debugging
		`,
		Run: func(cmd *cobra.Command, args []string) {
			parent := cmd.Parent()
			githubUrl, _ := parent.Flags().GetString("github")
			githubApiToken, _ := parent.Flags().GetString("token")

			client := pkgscan.SetupClient(githubApiToken, githubUrl)
			pkgrenovate.RunGenerate(client, autodiscoveryRepoName, autodiscoveryUsername, autodiscoveryAddWorkflow)
		},
	}
	autodiscoveryCmd.Flags().StringVarP(&autodiscoveryRepoName, "repo-name", "r", "", "The name for the created repository")
	autodiscoveryCmd.Flags().StringVarP(&autodiscoveryUsername, "username", "u", "", "The username of the victim Renovate Bot user to invite")
	autodiscoveryCmd.Flags().BoolVar(&autodiscoveryAddWorkflow, "add-renovate-workflow-for-debugging", false, "Creates a GitHub Actions workflow in the repo that runs Renovate Bot for local testing")

	return autodiscoveryCmd
}
