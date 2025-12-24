package variables

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgvariables "github.com/CompassSecurity/pipeleek/pkg/gitlab/variables"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewVariablesCmd() *cobra.Command {
	variablesCmd := &cobra.Command{
		Use:     "variables",
		Short:   "Print configured CI/CD variables",
		Long:    "Fetch and print all configured CI/CD variables for projects, groups and instance (if admin) your token has access to.",
		Example: `pipeleek gl variables --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com`,
		Run:     FetchVariables,
	}
	variablesCmd.Flags().StringP("gitlab", "g", "", "GitLab instance URL")
	variablesCmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return variablesCmd
}

func FetchVariables(cmd *cobra.Command, args []string) {
	if err := config.BindCommandFlags(cmd, "gitlab.variables", map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind flags")
	}

	if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
		log.Fatal().Err(err).Msg("Missing required configuration")
	}

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")

	if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab URL")
	}
	if err := config.ValidateToken(gitlabApiToken, "GitLab API Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab API Token")
	}

	pkgvariables.RunFetchVariables(gitlabUrl, gitlabApiToken)
}
