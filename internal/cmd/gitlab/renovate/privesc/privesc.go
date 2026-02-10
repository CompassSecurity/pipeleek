package privesc

import (
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/privesc"
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
		Short:   "Inject a malicious CI/CD Job into the protected default branch abusing Renovate Bot's access",
		Long:    "Inject a job into the CI/CD pipeline of the project's default branch by adding a commit (race condition) to a Renovate Bot branch, which is then auto-merged into the main branch. Assumes the Renovate Bot has owner/maintainer access whereas you only have developer access. See https://blog.compass-security.com/2025/05/renovate-keeping-your-updates-secure/",
		Example: `pipeleek gl renovate privesc --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com --repo-name mygroup/myproject --renovate-branches-regex 'renovate/.*'`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"gitlab":                  "gitlab.url",
				"token":                   "gitlab.token",
				"renovate-branches-regex": "gitlab.renovate.privesc.renovate_branches_regex",
				"repo-name":               "gitlab.renovate.privesc.repo_name",
				"monitoring-interval":     "gitlab.renovate.privesc.monitoring_interval",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			if err := config.RequireConfigKeys("gitlab.url", "gitlab.token", "gitlab.renovate.privesc.repo_name"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			privescRenovateBranchesRegex = config.GetString("gitlab.renovate.privesc.renovate_branches_regex")
			privescRepoName = config.GetString("gitlab.renovate.privesc.repo_name")
			privescMonitoringInterval = config.GetString("gitlab.renovate.privesc.monitoring_interval")

			// Validate monitoring interval early to ensure error appears on stderr for tests
			if _, err := time.ParseDuration(privescMonitoringInterval); err != nil {
				log.Fatal().Err(err).Msg("Failed to parse monitoring-interval duration")
			}

			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")
			pkgrenovate.RunExploit(gitlabUrl, gitlabApiToken, privescRepoName, privescRenovateBranchesRegex, privescMonitoringInterval)
		},
	}

	privescCmd.Flags().StringVarP(&privescRenovateBranchesRegex, "renovate-branches-regex", "b", "renovate/.*", "The branch name regex expression to match the Renovate Bot branch names (default: 'renovate/.*')")
	privescCmd.Flags().StringVarP(&privescRepoName, "repo-name", "r", "", "The repository to target")
	privescCmd.Flags().StringVarP(&privescMonitoringInterval, "monitoring-interval", "", "1s", "The interval to check for new Renovate branches (default: '1s')")

	// Validation handled via RequireConfigKeys

	return privescCmd
}
