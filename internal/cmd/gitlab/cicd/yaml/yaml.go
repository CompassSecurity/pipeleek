package yaml

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgcicd "github.com/CompassSecurity/pipeleek/pkg/gitlab/cicd/yaml"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url":   "gitlab.url",
	"token": "gitlab.token",
	"repo":  "gitlab.cicd.yaml.repo",
}

// RunYamlCommand handles the yaml command execution
func RunYamlCommand(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token", "gitlab.cicd.yaml.repo").
		MustBind()

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")
	projectName := config.GetString("gitlab.cicd.yaml.repo")

	pkgcicd.DumpCICDYaml(gitlabUrl, gitlabApiToken, projectName)
	log.Info().Msg("Done, Bye Bye 🏳️‍🌈🔥")
}

func NewYamlCmd() *cobra.Command {
	yamlCmd := &cobra.Command{
		Use:     "yaml",
		Short:   "Dump the CI/CD yaml configuration of a project",
		Long:    "Dump the CI/CD yaml configuration of a project, useful for analyzing the configuration and identifying potential security issues.",
		Example: `pipeleek gl cicd yaml --token glpat-xxxxxxxxxxx --url https://gitlab.mydomain.com --repo mygroup/myproject`,
		Run:     RunYamlCommand,
	}

	yamlCmd.Flags().String("repo", "", "Repository name")

	return yamlCmd
}
