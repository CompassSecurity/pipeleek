package secureFiles

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgsecurefiles "github.com/CompassSecurity/pipeleek/pkg/gitlab/secureFiles"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewSecureFilesCmd() *cobra.Command {
	secureFilesCmd := &cobra.Command{
		Use:     "secureFiles",
		Short:   "Print CI/CD secure files",
		Long:    "Fetch and print all CI/CD secure files for projects your token has access to.",
		Example: `pipeleek gl secureFiles --token glpat-xxxxxxxxxxx --gitlab https://gitlab.mydomain.com`,
		Run:     FetchSecureFiles,
	}
	secureFilesCmd.Flags().StringP("gitlab", "g", "", "GitLab instance URL")
	secureFilesCmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return secureFilesCmd
}

func FetchSecureFiles(cmd *cobra.Command, args []string) {
	if err := config.BindCommandFlags(cmd, "gitlab.secureFiles", map[string]string{
		"gitlab": "gitlab.url",
		"token":  "gitlab.token",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind flags")
	}

	if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
		log.Fatal().Err(err).Msg("required configuration missing")
	}

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")

	if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab URL")
	}
	if err := config.ValidateToken(gitlabApiToken, "GitLab API Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab API Token")
	}

	pkgsecurefiles.RunFetchSecureFiles(gitlabUrl, gitlabApiToken)
}
