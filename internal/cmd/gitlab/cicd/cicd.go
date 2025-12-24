package cicd

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/cicd/yaml"
	"github.com/spf13/cobra"
)

var (
	gitlabApiToken string
	gitlabUrl      string
)

func NewCiCdCmd() *cobra.Command {
	ciCdCmd := &cobra.Command{
		Use:   "cicd",
		Short: "CI/CD related commands",
	}

	ciCdCmd.PersistentFlags().StringVarP(&gitlabUrl, "gitlab", "g", "", "GitLab instance URL")
	ciCdCmd.PersistentFlags().StringVarP(&gitlabApiToken, "token", "t", "", "GitLab API Token")

	ciCdCmd.AddCommand(yaml.NewYamlCmd())

	return ciCdCmd
}
