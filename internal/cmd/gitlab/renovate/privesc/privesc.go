package privesc

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/privesc"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	privescRenovateBranchesRegex string
	privescRepoName              string
)

func NewPrivescCmd() *cobra.Command {
	privescCmd := &cobra.Command{
		Use:     "privesc",
		Short:   "Inject a malicious CI/CD Job into the protected default branch abusing Renovate Bot's access",
		Long:    "Inject a job into the CI/CD pipeline of the project's default branch by adding a commit (race condition) to a Renovate Bot branch, which is then auto-merged into the main branch. Assumes the Renovate Bot has owner/maintainer access whereas you only have developer access. See https://blog.compass-security.com/2025/05/renovate-keeping-your-updates-secure/",
		Example: `pipeleek gl renovate privesc --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com --repo-name mygroup/myproject --renovate-branches-regex 'renovate/.*'`,
		Run: func(cmd *cobra.Command, args []string) {
			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")
			pkgrenovate.RunExploit(gitlabUrl, gitlabApiToken, privescRepoName, privescRenovateBranchesRegex)
		},
	}
	privescCmd.Flags().StringVarP(&privescRenovateBranchesRegex, "renovate-branches-regex", "b", "renovate/.*", "The branch name regex expression to match the Renovate Bot branch names (default: 'renovate/.*')")
	privescCmd.Flags().StringVarP(&privescRepoName, "repo-name", "r", "", "The repository to target")

	err := privescCmd.MarkFlagRequired("repo-name")
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Unable to require repo-name flag")
	}

	return privescCmd
}
