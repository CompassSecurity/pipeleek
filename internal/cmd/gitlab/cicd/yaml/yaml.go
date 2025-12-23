package yaml

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgcicd "github.com/CompassSecurity/pipeleek/pkg/gitlab/cicd/yaml"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewYamlCmd() *cobra.Command {
	yamlCmd := &cobra.Command{
		Use:     "yaml",
		Short:   "Dump the CI/CD yaml configuration of a project",
		Long:    "Dump the CI/CD yaml configuration of a project, useful for analyzing the configuration and identifying potential security issues.",
		Example: `pipeleek gl cicd yaml --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com --project mygroup/myproject`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.BindCommandFlags(cmd, "gitlab.cicd.yaml", map[string]string{
				"gitlab": "gitlab.url",
				"token":  "gitlab.token",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind flags")
			}

			if err := config.RequireConfigKeys("gitlab.url", "gitlab.token", "gitlab.cicd.yaml.project"); err != nil {
				log.Fatal().Err(err).Msg("Missing required configuration")
			}

			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")
			projectName := config.GetString("gitlab.cicd.yaml.project")

			if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
				log.Fatal().Err(err).Msg("Invalid GitLab URL")
			}
			if err := config.ValidateToken(gitlabApiToken, "GitLab API Token"); err != nil {
				log.Fatal().Err(err).Msg("Invalid GitLab API Token")
			}

			pkgcicd.DumpCICDYaml(gitlabUrl, gitlabApiToken, projectName)
			log.Info().Msg("Done, Bye Bye 🏳️‍🌈🔥")
		},
	}

	yamlCmd.Flags().StringP("project", "p", "", "Project name")

	return yamlCmd
}
