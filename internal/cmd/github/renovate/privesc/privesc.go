package privesc

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/github/renovate/privesc"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	privescRenovateBranchesRegex string
	privescRepoName              string
	privescMonitoringInterval    string
)

func NewPrivescCmd() *cobra.Command {
	privescCmd := &cobra.Command{
		Use:     "privesc",
		Short:   "Inject a malicious workflow job into the protected default branch abusing Renovate Bot's access",
		Long:    "Inject a job into the GitHub Actions workflow of the repository's default branch by adding a commit (race condition) to a Renovate Bot branch, which is then auto-merged into the main branch. Assumes the Renovate Bot has owner/admin access whereas you only have write access. See https://blog.compass-security.com/2025/05/renovate-keeping-your-updates-secure/",
		Example: `pipeleek gh renovate privesc --token ghp_xxxxx --github https://api.github.com --repo-name owner/myproject --renovate-branches-regex 'renovate/.*'`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"github":                  "github.url",
				"token":                   "github.token",
				"renovate-branches-regex": "github.renovate.privesc.renovate_branches_regex",
				"repo-name":               "github.renovate.privesc.repo_name",
				"monitoring-interval":     "github.renovate.privesc.monitoring_interval",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			if err := config.RequireConfigKeys("github.token", "github.renovate.privesc.repo_name"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			privescRenovateBranchesRegex = config.GetString("github.renovate.privesc.renovate_branches_regex")
			privescRepoName = config.GetString("github.renovate.privesc.repo_name")
			privescMonitoringInterval = config.GetString("github.renovate.privesc.monitoring_interval")

			githubUrl := config.GetString("github.url")
			githubApiToken := config.GetString("github.token")

			client := pkgscan.SetupClient(githubApiToken, githubUrl)
			pkgrenovate.RunExploit(client, privescRepoName, privescRenovateBranchesRegex, privescMonitoringInterval)
		},
	}
	privescCmd.Flags().StringVarP(&privescRenovateBranchesRegex, "renovate-branches-regex", "b", "renovate/.*", "The branch name regex expression to match the Renovate Bot branch names (default: 'renovate/.*')")
	privescCmd.Flags().StringVarP(&privescRepoName, "repo-name", "r", "", "The repository to target in format owner/repo")
	privescCmd.Flags().StringVarP(&privescMonitoringInterval, "monitoring-interval", "", "1s", "The interval to check for new Renovate branches (default: '1s')")

	return privescCmd
}
