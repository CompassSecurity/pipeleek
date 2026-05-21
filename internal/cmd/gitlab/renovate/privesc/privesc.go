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
	privescProject               string
	privescMonitoringInterval    string
)

var flagBindings = map[string]string{
	"url":                     "gitlab.url",
	"token":                   "gitlab.token",
	"renovate-branches-regex": "gitlab.renovate.privesc.renovate_branches_regex",
	"repo":                    "gitlab.renovate.privesc.repo",
	"monitoring-interval":     "gitlab.renovate.privesc.monitoring_interval",
}

func NewPrivescCmd() *cobra.Command {
	privescCmd := &cobra.Command{
		Use:     "privesc",
		Short:   "Inject a malicious CI/CD Job into the protected default branch abusing Renovate Bot's access",
		Long:    "Inject a job into the CI/CD pipeline of the project's default branch by adding a commit (race condition) to a Renovate Bot branch, which is then auto-merged into the main branch. Assumes the Renovate Bot has owner/maintainer access whereas you only have developer access. See https://blog.compass-security.com/2025/05/renovate-keeping-your-updates-secure/",
		Example: `pipeleek gl renovate privesc --token glpat-xxxxxxxxxxx --url https://gitlab.mydomain.com --repo mygroup/myproject --renovate-branches-regex 'renovate/.*'`,
		Run: func(cmd *cobra.Command, args []string) {
			config.NewCommandSetup(cmd).
				WithFlagBindings(flagBindings).
				RequireKeys("gitlab.url", "gitlab.token", "gitlab.renovate.privesc.repo").
				MustBind()

			privescRenovateBranchesRegex = config.GetString("gitlab.renovate.privesc.renovate_branches_regex")
			privescProject = config.GetString("gitlab.renovate.privesc.repo")
			privescMonitoringInterval = config.GetString("gitlab.renovate.privesc.monitoring_interval")

			// Validate monitoring interval early to ensure error appears on stderr for tests
			if _, err := time.ParseDuration(privescMonitoringInterval); err != nil {
				log.Fatal().Err(err).Msg("Failed to parse monitoring-interval duration")
			}

			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")
			pkgrenovate.RunExploit(gitlabUrl, gitlabApiToken, privescProject, privescRenovateBranchesRegex, privescMonitoringInterval)
		},
	}

	privescCmd.Flags().StringVarP(&privescRenovateBranchesRegex, "renovate-branches-regex", "b", "renovate/.*", "The branch name regex expression to match the Renovate Bot branch names (default: 'renovate/.*')")
	privescCmd.Flags().StringVarP(&privescProject, "repo", "r", "", "The repository to target (format: namespace/repo)")
	privescCmd.Flags().StringVarP(&privescMonitoringInterval, "monitoring-interval", "", "1s", "The interval to check for new Renovate branches (default: '1s')")

	// Validation handled via RequireConfigKeys

	return privescCmd
}
